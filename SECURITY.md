# Security policy

## Secrets
Never commit Telegram, OpenAI, APIsec, or other credentials. Configure them only as deployment secrets.

## User data
The bot stores Telegram identifiers, usernames, questions, and answers in SQLite. Restrict access to the persistent disk, define a retention period before production use, and remove old tickets regularly.

## Reporting
Report suspected vulnerabilities privately to the repository owner. Do not include real credentials or customer data in an issue.
