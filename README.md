# Domain Threat Intelligence Agent

Master’s thesis in cybersecurity project on malicious domains' detection. Scanning agent.
Uses scanning capabilities to detect malicious activity ob remotes hosts.

This project is mirrored from GitLab.

Links:

- [Main project on GitLab](https://gitlab.qvineox.ru/masters/domain-threat-intelligence-agent)
- [Mirror on GitHub](https://github.com/Qvineox/domain-threat-intelligence-agent-mirror)
- [Master's thesis paper](https://cloud.qvineox.ru/index.php/s/wLg8bncwQWz9Tff)

Ecosystem:

- Hub
    - Main project on [GitLab](https://gitlab.qvineox.ru/masters/domain-threat-intelligence-hub)
    - Mirror on [GitHub](https://github.com/Qvineox/domain-threat-intelligence-hub-mirror)
- API
    - Main project on [GitLab](https://gitlab.qvineox.ru/masters/domain-threat-intelligence-api)
    - Mirror on [GitHub](https://github.com/Qvineox/domain-threat-intelligence-api-mirror)

    
## Project structure

The Go language maintainer has no strong convention about structuring a project in Go. However, one layout has emerged
over the years: [project-layout](https://github.com/golang-standards/project-layout).
If our project is small enough (only a few files), or if our organization has already created its standard, it may not
be worth using or migrating to project-layout. Other-wise, it might be worth considering. Let’s look at this layout and
see what the main directories are:

- `/cmd` - The main source files.
    - `/app` - Application startup logic.
    - `/core` - Main application code.
        - `/entities` - Core domain model of the application.
        - `/repos` - Repositories to manipulate stored data.
        - `/services` - Defines domain logic using domain models.
    - `/oss` - Open Source scanners' code
- `/internal` - Private code not importing to other applications or libraries.
- `/pkg` - Public code exposed to others.
- `/test` - Additional external tests and test data.
- `/configs` - Configuration files.
- `/docs` - Design and user documents.
- `/examples` - Examples for our application and/or a public library.
- `/api` - API contract files (Swagger, Protocol Buffers, etc.).
    - `/proto` - Files used in Protocol Buffers/gRPC communication.
    - `/services` - Web API endpoints.
- `/web` - Web application-specific assets (static files, etc.).
- `/build` - Packaging and continuous integration (CI) files.
    - `/bin` - Binary and compilation files.
- `/scripts` - Scripts for analysis, installation, and so on.
    - `/docker` - Docker compose files to start the application.
    - `/idea` - IDE development scripts.
- `/vendor` - Application dependencies (for example, Go modules dependencies).

There’s no /src directory like in some other languages. The rationale is that /src is too generic; hence, this layout
favors directories such as /cmd, /internal, or /pkg.

> Source: Manning, 100 Go Mistakes and How to Avoid Them

## Security and compliance

> TODO: add security and compliance data...
