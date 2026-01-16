<p align="center">
    <a href="https://github.com/OpsLevel/opslevel-mcp/blob/main/LICENSE">
        <img src="https://img.shields.io/github/license/OpsLevel/opslevel-mcp.svg" alt="License" /></a>
    <a href="https://GitHub.com/OpsLevel/opslevel-mcp/releases/">
        <img src="https://img.shields.io/github/v/release/OpsLevel/opslevel-mcp" alt="Release" /></a>
    <a href="https://github.com/OpsLevel/opslevel-mcp/actions/workflows/tests.yml">
        <img src="https://github.com/OpsLevel/opslevel-mcp/actions/workflows/tests.yml/badge.svg" alt="Tests" /></a>
    <a href="https://github.com/OpsLevel/opslevel-mcp/actions/workflows/mcp-eval-tests.yml">
        <img src="https://github.com/OpsLevel/opslevel-mcp/actions/workflows/mcp-eval-tests.yml/badge.svg" alt="MCP Eval Tests" /></a>
    <a href="https://masterminds.github.io/stability/active.html">
        <img src="https://masterminds.github.io/stability/active.svg" alt="Stability: Active" /></a>
    <a href="https://github.com/OpsLevel/opslevel-mcp/graphs/contributors">
        <img src="https://img.shields.io/github/contributors/OpsLevel/opslevel-mcp" alt="Contributors" /></a>
    <a href="https://github.com/OpsLevel/opslevel-mcp/pulse">
        <img src="https://img.shields.io/github/commit-activity/m/OpsLevel/opslevel-mcp" alt="Activity" /></a>
    <a href="https://github.com/OpsLevel/opslevel-mcp/releases">
        <img src="https://img.shields.io/github/downloads/OpsLevel/opslevel-mcp/total" alt="Downloads" /></a>
    <a href="https://app.opslevel.com/services/opslevel_mcp/maturity-report">
        <img src="https://img.shields.io/endpoint?style=flat&url=https%3A%2F%2Fapp.opslevel.com%2Fapi%2Fservice_level%2Fdlmj6PlFjehv6iLE6IQtEGXi_uz3LF9rA5nxb35wiY8" alt="Overall" /></a>

[![Trust Score](https://archestra.ai/mcp-catalog/api/badge/quality/opslevel/opslevel-mcp)](https://archestra.ai/mcp-catalog/opslevel__opslevel-mcp)
</p>

<p align="center">
  <a href="https://glama.ai/mcp/servers/@OpsLevel/opslevel-mcp">
    <img width="380" height="200" src="https://glama.ai/mcp/servers/@OpsLevel/opslevel-mcp/badge" />
  </a>
</p>


# OpsLevel MCP Server

This MCP ([Model Context Protocol](https://modelcontextprotocol.io/introduction)) server provides AIs with tools to interact with your OpsLevel account.

![mcp_image](https://github.com/user-attachments/assets/dd936eef-80c2-42a5-8d04-9ca9c2de8e76)

# Features

Currently, the MCP server only uses read-only access to your OpsLevel account and can read data from the following resources:

- Actions
- Campaigns
- Checks
- Components
- Documentation (API & Tech Docs)
- Domains
- Filters
- Infrastructure
- Repositories
- Systems
- Teams
- Users

# Setup

1. Install the MCP Server
   1. Homebrew - `brew install opslevel/tap/opslevel-mcp`
   2. Docker - `docker pull public.ecr.aws/opslevel/mcp:latest`  
      You can also used a pinned version [check out the gallery for the available tags](https://gallery.ecr.aws/opslevel/mcp) 
   3. Manual - Visit our [GitHub releases page](https://github.com/OpsLevel/opslevel-mcp/releases) and download the binary for your operating system.
2. You will need an [API Token](https://app.opslevel.com/api_tokens) to authorize the MCP Server to talk to your account via an environment variable.
3. Setup MCP configuration for the AI tool of your choice.

## Claude

[Claude Desktop](https://modelcontextprotocol.io/quickstart/user)

1. Edit the file at the specified path based on the Claude Desktop docs
   1. Mac OS - `${HOME}/Library/Application\ Support/Claude/claude_desktop_config.json`
   2. Windows - `%APPDATA%\Claude\claude_desktop_config.json`
2. Start (or restart) Claude Desktop

```json
{
    "mcpServers": {
        "opslevel": {
            "command": "opslevel-mcp",
            "env": {
                "OPSLEVEL_API_TOKEN": "XXXXXXX"
            }
        }
    }
}
```

## VS Code

[VS Code User Settings](https://code.visualstudio.com/docs/copilot/chat/mcp-servers#_finding-mcp-servers)

1. Open the Settings menu (Command + Comma) and select the correct tab atop the page for your use case
   1. Workspace - configures the server in the context of your workspace
   2. User - configures the server in the context of your user
2. Select Features → Chat
3. Ensure that "Mcp" is Enabled
   1. You may need to have your Github administrator enable "preview" features in the CoPilot settings for the organization.
4. Click "Edit in settings.json" under "Mcp > Discovery" to have the below config
   1. Can also edit the file directly
      1. (Mac OS)  `${HOME}/Library/Application\\ Support/Code/User/settings.json`
5. Start (or restart) VS Code

```json
{
    "chat.agent.enabled": true,
    "chat.mcp.discovery.enabled": true,
    "mcp": {
        "inputs": [
          {
            "type": "promptString",
            "id": "opslevel_token",
            "description": "OpsLevel API Token",
            "password": true
          }
        ],
        "servers": {
            "opslevel": {
                "type": "stdio",
                "command": "opslevel-mcp",
                "env": {
                    "OPSLEVEL_API_TOKEN": "${input:opslevel_token}"
                }
            }
        }
    }
}
```

## Cursor

[Cursor Docs](https://docs.cursor.com/context/model-context-protocol)

[![Install MCP Server](https://cursor.com/deeplink/mcp-install-dark.png)](cursor://anysphere.cursor-deeplink/mcp/install?name=opslevel&config=eyJjb21tYW5kIjoib3BzbGV2ZWwtbWNwIiwiZW52Ijp7Ik9QU0xFVkVMX0FQSV9UT0tFTiI6IlhYWFhYWCJ9fQ==)

1. Open the Cursor menu and select Settings → Cursor Settings → MCP
2. Click "Add new global MCP server"
3. Add the config below

```json
{
  "mcpServers": {
    "opslevel": {
      "command": "opslevel-mcp",  
      "env": {
        "OPSLEVEL_API_TOKEN": "XXXXXX"
      }
    }
  }
}
```

## Warp

[Warp](https://www.warp.dev/)

1. Access your MCP settings under Settings > AI > Manage MCP Servers. Warp provides [instructions for other ways to access this list.](https://docs.warp.dev/knowledge-and-collaboration/mcp#how-to-access-mcp-server-settings)
2. Press the add button
3. Add the config below

```json
{
  "opslevel": {
    "command": "opslevel-mcp",
    "args": [],
    "env": {
      "OPSLEVEL_API_TOKEN": "XXXXXX"
    },
    "start_on_launch": true
  }
}
```

## Windsurf

[Windsurf](https://windsurf.com/editor)

1. Navigate to Windsurf - Settings > Advanced Settings
2. Scroll down to the Cascade section and you will find the option to add a new server
3. Edit the [mpc_config.json](https://docs.windsurf.com/windsurf/mcp#mcp-config-json) with the below configuration
4. Restart Windsurf

```json
{
  "mcpServers": {
    "opslevel": {
      "command": "opslevel-mcp",  
      "env": {
        "OPSLEVEL_API_TOKEN": "XXXXXX"
      }
    }
  }
}
```

### Docker

If you didn't install the binary directly and instead pulled the docker image you'll need to adjust the above MCP configurations to support running the server via docker

```
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "-e",
          "OPSLEVEL_API_TOKEN",
          "public.ecr.aws/opslevel/mcp:latest"
        ],
```

# Development

## Testing

This repository uses a comprehensive test suite to ensure code quality and functionality.

### Running Tests

#### Go Tests

The Go codebase (main MCP server) includes unit tests for core functionality:

```bash
# Run all Go tests
cd src
go test ./...

# Run tests with coverage
go test -race -coverprofile=coverage.txt -covermode=atomic ./...

# Run tests with verbose output
go test -v ./...
```

#### JavaScript Tests

The `mcp-eval` evaluation framework includes Jest-based tests:

```bash
# Run all JavaScript tests
cd mcp-eval
npm test

# Run tests in watch mode
npm test -- --watch
```

#### Using Task

The repository uses [Task](https://taskfile.dev/) as a task runner. To run the full CI pipeline locally:

```bash
# Run linting and tests
task ci

# Run only tests
task test

# Run only linting
task lint
```

### Continuous Integration

All tests are automatically run on:
- Pull requests to the main branch
- Pushes to the main branch

The CI pipeline runs linting, formatting checks, and the complete test suite to ensure code quality.
