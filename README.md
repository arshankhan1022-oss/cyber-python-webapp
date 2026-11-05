# Cloud-Based Cybersecurity Log Monitoring and Alert System

Flask + Azure Cosmos DB + Azure App Service, with an Application Insights monitor, managed-identity access and email/webhook alerts.
Rule: **5 failed logins from one source within 5 minutes → "Suspicious Activity" alert** (one open alert per source per window).

## Pages
| URL | Access | Purpose |
|---|---|---|
| `/login` | public | Demo target. Accounts `admin / Admin@123`, `student / Student@123`. Every attempt is logged (never the password). |
| `/` `/logs` `/alerts` | dashboard login (`ADMIN_USER` / `ADMIN_PASSWORD`) | Counts, hourly chart (Chart.js), events, alerts, Resolve button, test-event buttons. |

## 1. Run locally (works without Azure)
```
python -m venv .venv && .venv\Scripts\activate      # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
copy .env.example .env                               # edit values (cp on Linux/macOS)
python app.py                                        # http://127.0.0.1:5000
```
`.env.example` has the Cosmos lines commented out; uncomment them once you have real values. No `COSMOS_ENDPOINT` → badge shows **Local demo (in-memory)**. With it → **Azure Cosmos DB**.

## 2. Azure resources
Names must be globally unique; change them if taken.
```
az login
az group create -n rg-cybersecurity-demo -l eastus
az cosmosdb create -n cosmos-cybersecurity -g rg-cybersecurity-demo
az cosmosdb show -n cosmos-cybersecurity -g rg-cybersecurity-demo --query documentEndpoint -o tsv
az cosmosdb keys list -n cosmos-cybersecurity -g rg-cybersecurity-demo --query primaryMasterKey -o tsv
```

## 3. Deploy to App Service
```
az webapp up -n cybersecurity-demo-app -g rg-cybersecurity-demo -l eastus --runtime "PYTHON:3.12" --sku B1
az webapp config appsettings set -g rg-cybersecurity-demo -n cybersecurity-demo-app --settings COSMOS_ENDPOINT="<endpoint>" COSMOS_KEY="<key>" ADMIN_PASSWORD="<strong-password>"
```
Check current pricing for your tier (F1 may work on a student subscription). If the app won't start, set the startup command to `gunicorn --bind=0.0.0.0 --timeout 600 app:app`.

## 4. Managed identity (no database key)
With `COSMOS_ENDPOINT` set and **no** `COSMOS_KEY`, the app signs in with `DefaultAzureCredential`: the App Service identity in Azure, your `az login` locally. Identity access can read and write data but cannot create databases, so create them first:
```
az cosmosdb sql database create --account-name cosmos-cybersecurity -g rg-cybersecurity-demo --name cybersecurity_demo
az cosmosdb sql container create --account-name cosmos-cybersecurity -g rg-cybersecurity-demo --database-name cybersecurity_demo --name security_logs --partition-key-path /source
az cosmosdb sql container create --account-name cosmos-cybersecurity -g rg-cybersecurity-demo --database-name cybersecurity_demo --name security_alerts --partition-key-path /source

az webapp identity assign -n cybersecurity-demo-app -g rg-cybersecurity-demo --query principalId -o tsv
az cosmosdb sql role assignment create --account-name cosmos-cybersecurity -g rg-cybersecurity-demo --scope "/" --principal-id <principalId> --role-definition-id 00000000-0000-0000-0000-000000000002
az webapp config appsettings delete -n cybersecurity-demo-app -g rg-cybersecurity-demo --setting-names COSMOS_KEY
```
(`00000000-0000-0000-0000-000000000002` is Cosmos DB Built-in Data Contributor.) For local runs with identity, give your own user the same role (`az ad signed-in-user show --query id -o tsv` gives your principal ID) and remove `COSMOS_KEY` from `.env`. Role assignments can take a few minutes to apply.

## 5. Application Insights
Portal → **Create a resource → Application Insights** (same resource group) → copy the **Connection String** from Overview, then:
```
az webapp config appsettings set -g rg-cybersecurity-demo -n cybersecurity-demo-app --settings APPLICATIONINSIGHTS_CONNECTION_STRING="<connection-string>"
```
Browse the app, then open Application Insights → **Logs** and run:
```
traces | where message startswith "security_alert" or message startswith "login_event" | order by timestamp desc
```
Also useful for screenshots: Live metrics, Failures, Performance (requests are tracked automatically).

## 6. Alert delivery (optional, either or both)
**SMTP email (easiest):** set `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `ALERT_EMAIL_TO`. For Gmail use `smtp.gmail.com`, port 587, 2-step verification on, and an App Password.
**Azure Logic App (cloud workflow):** Portal → Create **Logic App (Consumption)** → Designer → trigger **When an HTTP request is received** (use sample payload `{"type":"Suspicious Activity","severity":"High","source":"203.0.113.7","failed_attempts":5,"message":"...","created_at":"..."}`) → add **Send an email (V2)** with your Outlook/Gmail connector → Save → copy the trigger's **HTTP POST URL** into `ALERT_WEBHOOK_URL`. Menu labels may differ slightly. Treat that URL as a secret.
Delivery failures are logged as warnings and never block logins.

## 7. Demo script
1. `/login`: one correct sign-in, then 5 wrong ones. 2. Dashboard: show counts, chart bar, alert (and the email arriving). 3. Cosmos Data Explorer: `SELECT * FROM c ORDER BY c.timestamp DESC`. 4. Application Insights: run the `traces` query. 5. Resolve the alert on `/alerts`.

## 8. Screenshots (report Chapter 4)
Original 1–10 as before (Step 8 must show the `*.azurewebsites.net` URL), plus: chart on the dashboard, the alert email or Logic App run history, App Service **Identity** page, Cosmos **role assignment** output, Application Insights query result. Hide keys and connection strings.

## Security notes
Passwords hashed, never logged; secrets in `.env` (git-ignored) or App Service settings; dashboard needs a login; alert emails contain no credentials. Demo-grade rule: expect false positives and negatives. Delete the resource group when finished: `az group delete -n rg-cybersecurity-demo`.
