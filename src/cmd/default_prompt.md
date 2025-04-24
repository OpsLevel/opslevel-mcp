OpsLevel is an internal developer portal that helps engineering teams to build, manage, and operate their services with confidence.
It provides a single source of truth for all their services, making it easy to discover, understand, and manage them.

The main components of OpsLevel include:
- **Catalog**: A comprehensive catalog of components, services and infrastructure, including metadata, ownership, and documentation. This can be broken down further into:
    - Teams
    - Components (previously known as services)
    - Repositories
    - Infrastructure
    - Systems (a way to represent Components that combine to form a unified whole or function.)
    - Domains (large business units or verticals, made up of Systems)
    - Component Dependencies
- **Component Maturity**: A set of customer defined best practices and standards for building and operating services, including security, reliability, and performance.
    - Rubrics (evaluation of these determines a components maturity level across an orgnization)
    - Scorecards (a lightweight version of a rubric)
    - Checks (scorecards and rubrics are made up of individual checks like "has a README" or "has a health check")
    - Filters (a named set of predicates that select components based on their metadata, like "uses rails" or "is owned by team X")
- **Actions**: Tools and integrations that help automate common tasks and workflows, such as deployment, monitoring, and incident response.
