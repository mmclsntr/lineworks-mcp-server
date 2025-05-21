import logging
import secrets
import time
from typing import Any, Literal

import click
from pydantic import AnyHttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.fastmcp.server import FastMCP
from mcp.shared._httpx_utils import create_mcp_http_client
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

logger = logging.getLogger(__name__)


class ServerSettings(BaseSettings):
    """Settings for the simple WORKS MCP server."""

    model_config = SettingsConfigDict(env_prefix="MCP_WORKS_")

    # Server settings
    host: str = "localhost"
    port: int = 8000
    server_url: AnyHttpUrl = AnyHttpUrl("http://localhost:8000")

    # OAuth settings - MUST be provided via environment variables
    works_client_id: str  # Type: MCP_WORKS_WORKS_CLIENT_ID env var
    works_client_secret: str  # Type: MCP_WORKS_WORKS_CLIENT_SECRET env var
    #works_callback_path: str = "http://localhost:8000/redirect"
    works_callback_path: str = "http://localhost:8000/redirect"

    # OAuth URLs
    works_auth_url: str = "https://auth.worksmobile.com/oauth2/v2.0/authorize"
    works_token_url: str = "https://auth.worksmobile.com/oauth2/v2.0/token"

    mcp_scope: str = "user"
    works_scope: str = "user.read"

    def __init__(self, **data):
        """Initialize settings with values from environment variables.
        """
        super().__init__(**data)



class WorksOAuthProvider(OAuthAuthorizationServerProvider):
    """WORKS OAuth provider with essential functionality."""

    def __init__(self, settings: ServerSettings):
        self.settings = settings
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.auth_codes: dict[str, AuthorizationCode] = {}
        self.tokens: dict[str, AccessToken] = {}
        self.state_mapping: dict[str, dict[str, str]] = {}
        # Store tokens with MCP tokens using the format:
        # {"mcp_token": "token"}
        self.token_mapping: dict[str, str] = {}

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        """Get OAuth client information."""
        return self.clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull):
        """Register a new OAuth client."""
        self.clients[client_info.client_id] = client_info

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        """Generate an authorization URL for OAuth flow."""
        state = params.state or secrets.token_hex(8)

        # Store the state mapping
        self.state_mapping[state] = {
            "redirect_uri": str(params.redirect_uri),
            "code_challenge": params.code_challenge,
            "redirect_uri_provided_explicitly": str(
                params.redirect_uri_provided_explicitly
            ),
            "client_id": client.client_id,
        }

        # Build authorization URL
        auth_url = (
            f"{self.settings.works_auth_url}"
            f"?client_id={self.settings.works_client_id}"
            f"&redirect_uri={self.settings.works_callback_path}"
            f"&scope={self.settings.works_scope}"
            f"&response_type=code&state={state}"
        )

        logger.info(auth_url)

        return auth_url

    async def handle_callback(self, code: str, state: str) -> str:
        """Handle OAuth callback."""
        state_data = self.state_mapping.get(state)
        if not state_data:
            raise HTTPException(400, "Invalid state parameter")

        logger.info(state_data)

        redirect_uri = state_data["redirect_uri"]
        code_challenge = state_data["code_challenge"]
        redirect_uri_provided_explicitly = (
            state_data["redirect_uri_provided_explicitly"] == "True"
        )
        client_id = state_data["client_id"]

        # Exchange code for token
        async with create_mcp_http_client() as client:
            response = await client.post(
                self.settings.works_token_url,
                data={
                    "client_id": self.settings.works_client_id,
                    "client_secret": self.settings.works_client_secret,
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": self.settings.works_callback_path,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            #if response.status_code != 200:
            #    raise HTTPException(400, "Failed to exchange code for token")

            data = response.json()
            logger.info(data)

            if "error" in data:
                raise HTTPException(400, data.get("error_description", data["error"]))

            works_token = data["access_token"]

            # Create MCP authorization code
            new_code = f"mcp_{secrets.token_hex(16)}"
            auth_code = AuthorizationCode(
                code=new_code,
                client_id=client_id,
                redirect_uri=AnyHttpUrl(redirect_uri),
                redirect_uri_provided_explicitly=redirect_uri_provided_explicitly,
                expires_at=time.time() + 300,
                scopes=[self.settings.mcp_scope],
                code_challenge=code_challenge,
            )
            self.auth_codes[new_code] = auth_code

            # Store token - we'll map the MCP token to this later
            self.tokens[works_token] = AccessToken(
                token=works_token,
                client_id=client_id,
                scopes=[self.settings.works_scope],
                expires_at=None,
            )

            logger.info(self.auth_codes)
            logger.info(self.tokens)

        del self.state_mapping[state]
        return construct_redirect_uri(redirect_uri, code=new_code, state=state)

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        """Load an authorization code."""
        return self.auth_codes.get(authorization_code)

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        """Exchange authorization code for tokens."""
        if authorization_code.code not in self.auth_codes:
            raise ValueError("Invalid authorization code")

        # Generate MCP access token
        mcp_token = f"mcp_{secrets.token_hex(32)}"

        # Store MCP token
        self.tokens[mcp_token] = AccessToken(
            token=mcp_token,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=int(time.time()) + 3600,
        )

        # Find token for this client
        works_token = next(
            (
                token
                for token, data in self.tokens.items()
                if data.client_id == client.client_id
            ),
            None,
        )

        # Store mapping between MCP token and WORKS token
        if works_token:
            self.token_mapping[mcp_token] = works_token

        del self.auth_codes[authorization_code.code]

        return OAuthToken(
            access_token=mcp_token,
            token_type="bearer",
            expires_in=3600,
            scope=" ".join(authorization_code.scopes),
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        """Load and validate an access token."""
        access_token = self.tokens.get(token)
        if not access_token:
            return None

        # Check if expired
        if access_token.expires_at and access_token.expires_at < time.time():
            del self.tokens[token]
            return None

        return access_token

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        """Load a refresh token - not supported."""
        return None

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        """Exchange refresh token"""
        raise NotImplementedError("Not supported")

    async def revoke_token(
        self, token: str, token_type_hint: str | None = None
    ) -> None:
        """Revoke a token."""
        if token in self.tokens:
            del self.tokens[token]


def create_simple_mcp_server(settings: ServerSettings) -> FastMCP:
    """Create a simple FastMCP server with OAuth."""
    oauth_provider = WorksOAuthProvider(settings)

    auth_settings = AuthSettings(
        issuer_url=settings.server_url,
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            valid_scopes=[settings.mcp_scope],
            default_scopes=[settings.mcp_scope],
        ),
        required_scopes=[settings.mcp_scope],
    )

    app = FastMCP(
        name="WORKS MCP Server",
        instructions="WORKS MCP Server",
        auth_server_provider=oauth_provider,
        host=settings.host,
        port=settings.port,
        debug=True,
        auth=auth_settings,
        stateless_http=True,
    )

    @app.custom_route("/redirect", methods=["GET"])
    async def redirect_handler(request: Request) -> Response:
        """Handle Redirect OAuth callback."""
        code = request.query_params.get("code")
        state = request.query_params.get("state")

        if not code or not state:
            raise HTTPException(400, "Missing code or state parameter")

        try:
            redirect_uri = await oauth_provider.handle_callback(code, state)
            return RedirectResponse(status_code=302, url=redirect_uri)
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Unexpected error", exc_info=e)
            return JSONResponse(
                status_code=500,
                content={
                    "error": "server_error",
                    "error_description": "Unexpected error",
                },
            )

    def get_works_token() -> str:
        """Get the WORKS token for the authenticated user."""
        access_token = get_access_token()
        if not access_token:
            raise ValueError("Not authenticated")

        # Get WORKS token from mapping
        works_token = oauth_provider.token_mapping.get(access_token.token)

        if not works_token:
            raise ValueError("No token found for user")

        return works_token

    @app.tool()
    async def get_user_profile() -> dict[str, Any]:
        """Get the authenticated user's profile information.

        This is the only tool in our simple example. It requires the 'user' scope.
        """
        works_token = get_works_token()

        async with create_mcp_http_client() as client:
            response = await client.get(
                "https://www.worksapis.com/v1.0/users/me",
                headers={
                    "Authorization": f"Bearer {works_token}",
                    "Accept": "application/json; charset=UTF-8",
                },
            )

            if response.status_code != 200:
                raise ValueError(
                    f"API error: {response.status_code} - {response.text}"
                )

            return response.json()

    return app


logging.basicConfig(level=logging.DEBUG)

try:
    # No hardcoded credentials - all from environment variables
    settings = ServerSettings()
except ValueError as e:
    logger.error(
        "Failed to load settings. Make sure environment variables are set:"
    )
    logger.error("  MCP_WORKS_WORKS_CLIENT_ID=<your-client-id>")
    logger.error("  MCP_WORKS_WORKS_CLIENT_SECRET=<your-client-secret>")
    logger.error(f"Error: {e}")
    exit(1)

transport = "streamable-http"
#transport = "sse"
mcp = create_simple_mcp_server(settings)
logger.info(f"Starting server with {transport} transport")
mcp.run(transport=transport)
