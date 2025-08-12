# Deployment Guide - GST Verification API

This guide provides comprehensive instructions for deploying the GST Verification API across different platforms and environments.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Environment Configuration](#environment-configuration)
- [Local Development](#local-development)
- [Docker Deployment](#docker-deployment)
- [Cloud Deployments](#cloud-deployments)
  - [Azure App Service](#azure-app-service)
  - [AWS Lambda](#aws-lambda)
  - [Google Cloud Run](#google-cloud-run)
  - [Heroku](#heroku)
- [Traditional Server Deployment](#traditional-server-deployment)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Monitoring and Logging](#monitoring-and-logging)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)

## Prerequisites

- Python 3.8 or higher
- Git
- Docker (for containerized deployments)
- Cloud CLI tools (for cloud deployments)

## Environment Configuration

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/GST-Verification-API.git
cd GST-Verification-API
```

### 2. Environment Variables

Copy the example environment file and configure it:

```bash
cp .env.example .env
```

Edit `.env` with your specific configuration:

```bash
# Application Configuration
FLASK_ENV=production
DEBUG=false
PORT=5001
SECRET_KEY=your-super-secret-key-here

# Logging
LOG_LEVEL=INFO
LOG_FILE=/var/log/gst-api/app.log

# Session Management
SESSION_TIMEOUT=1800
MAX_SESSIONS=1000

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_PER_MINUTE=60
RATE_LIMIT_BURST=10

# CORS
CORS_ORIGINS=https://yourdomain.com,https://api.yourdomain.com

# External Services (Optional)
REDIS_URL=redis://localhost:6379/0
SENTRY_DSN=your-sentry-dsn
API_KEY=your-api-key
```

## Local Development

### Using Python Virtual Environment

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

### Using Docker Compose

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f gst-api

# Stop services
docker-compose down
```

## Docker Deployment

### Build and Run Docker Container

```bash
# Build the image
docker build -t gst-verification-api .

# Run the container
docker run -d \
  --name gst-api \
  -p 5001:5001 \
  -e FLASK_ENV=production \
  -e SECRET_KEY=your-secret-key \
  --restart unless-stopped \
  gst-verification-api
```

### Docker with Environment File

```bash
docker run -d \
  --name gst-api \
  -p 5001:5001 \
  --env-file .env \
  --restart unless-stopped \
  gst-verification-api
```

## Cloud Deployments

### Azure App Service

#### Using Azure CLI

```bash
# Login to Azure
az login

# Create resource group
az group create --name gst-api-rg --location "East US"

# Create App Service plan
az appservice plan create \
  --name gst-api-plan \
  --resource-group gst-api-rg \
  --sku B1 \
  --is-linux

# Create web app
az webapp create \
  --resource-group gst-api-rg \
  --plan gst-api-plan \
  --name your-gst-api \
  --runtime "PYTHON|3.9"

# Configure app settings
az webapp config appsettings set \
  --resource-group gst-api-rg \
  --name your-gst-api \
  --settings \
    FLASK_ENV=production \
    SECRET_KEY=your-secret-key \
    SCM_DO_BUILD_DURING_DEPLOYMENT=true

# Deploy code
az webapp deployment source config-zip \
  --resource-group gst-api-rg \
  --name your-gst-api \
  --src release.zip
```

#### Using GitHub Actions

The repository includes a comprehensive GitHub Actions workflow that automatically:
- Runs code quality checks
- Executes tests across multiple Python versions
- Performs security scans
- Builds and tests Docker images
- Deploys to Azure App Service

### AWS Lambda

#### Using Serverless Framework

1. Install Serverless Framework:
```bash
npm install -g serverless
npm install serverless-python-requirements
```

2. Create `serverless.yml`:
```yaml
service: gst-verification-api

provider:
  name: aws
  runtime: python3.9
  region: us-east-1
  environment:
    FLASK_ENV: production
    SECRET_KEY: ${env:SECRET_KEY}

functions:
  app:
    handler: lambda_handler.handler
    events:
      - http:
          path: /{proxy+}
          method: ANY
          cors: true
      - http:
          path: /
          method: ANY
          cors: true

plugins:
  - serverless-python-requirements

custom:
  pythonRequirements:
    dockerizePip: true
```

3. Create `lambda_handler.py`:
```python
from app import app
from serverless_wsgi import handle_request

def handler(event, context):
    return handle_request(app, event, context)
```

4. Deploy:
```bash
serverless deploy
```

### Google Cloud Run

```bash
# Build and push to Google Container Registry
gcloud builds submit --tag gcr.io/PROJECT_ID/gst-verification-api

# Deploy to Cloud Run
gcloud run deploy gst-verification-api \
  --image gcr.io/PROJECT_ID/gst-verification-api \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars FLASK_ENV=production,SECRET_KEY=your-secret-key
```

### Heroku

1. Create `Procfile`:
```
web: gunicorn app:app --bind 0.0.0.0:$PORT --workers 4 --timeout 120
```

2. Deploy:
```bash
# Login to Heroku
heroku login

# Create app
heroku create your-gst-api

# Set environment variables
heroku config:set FLASK_ENV=production
heroku config:set SECRET_KEY=your-secret-key

# Deploy
git push heroku main
```

## Traditional Server Deployment

### Using Gunicorn with Nginx

#### 1. Install Dependencies

```bash
sudo apt update
sudo apt install python3-pip python3-venv nginx
```

#### 2. Setup Application

```bash
# Create application directory
sudo mkdir -p /var/www/gst-api
cd /var/www/gst-api

# Clone repository
sudo git clone https://github.com/your-username/GST-Verification-API.git .

# Create virtual environment
sudo python3 -m venv venv
sudo chown -R www-data:www-data /var/www/gst-api

# Install dependencies
sudo -u www-data venv/bin/pip install -r requirements.txt
```

#### 3. Create Systemd Service

Create `/etc/systemd/system/gst-api.service`:

```ini
[Unit]
Description=GST Verification API
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/var/www/gst-api
Environment="PATH=/var/www/gst-api/venv/bin"
EnvironmentFile=/var/www/gst-api/.env
ExecStart=/var/www/gst-api/venv/bin/gunicorn --workers 4 --bind unix:gst-api.sock -m 007 app:app
Restart=always

[Install]
WantedBy=multi-user.target
```

#### 4. Configure Nginx

Create `/etc/nginx/sites-available/gst-api`:

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        include proxy_params;
        proxy_pass http://unix:/var/www/gst-api/gst-api.sock;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
}
```

#### 5. Enable and Start Services

```bash
# Enable and start the application service
sudo systemctl enable gst-api
sudo systemctl start gst-api

# Enable Nginx site
sudo ln -s /etc/nginx/sites-available/gst-api /etc/nginx/sites-enabled
sudo nginx -t
sudo systemctl restart nginx
```

## Kubernetes Deployment

### 1. Create Kubernetes Manifests

#### Deployment (`k8s/deployment.yaml`):

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: gst-verification-api
  labels:
    app: gst-verification-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: gst-verification-api
  template:
    metadata:
      labels:
        app: gst-verification-api
    spec:
      containers:
      - name: gst-api
        image: your-registry/gst-verification-api:latest
        ports:
        - containerPort: 5001
        env:
        - name: FLASK_ENV
          value: "production"
        - name: SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: gst-api-secrets
              key: secret-key
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /api/v1/health
            port: 5001
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /api/v1/health
            port: 5001
          initialDelaySeconds: 5
          periodSeconds: 5
```

#### Service (`k8s/service.yaml`):

```yaml
apiVersion: v1
kind: Service
metadata:
  name: gst-verification-api-service
spec:
  selector:
    app: gst-verification-api
  ports:
    - protocol: TCP
      port: 80
      targetPort: 5001
  type: LoadBalancer
```

#### Secret (`k8s/secret.yaml`):

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: gst-api-secrets
type: Opaque
data:
  secret-key: <base64-encoded-secret-key>
```

### 2. Deploy to Kubernetes

```bash
# Apply manifests
kubectl apply -f k8s/

# Check deployment status
kubectl get deployments
kubectl get pods
kubectl get services

# View logs
kubectl logs -f deployment/gst-verification-api
```

## Monitoring and Logging

### Application Monitoring

#### Health Checks

The API includes a health check endpoint at `/api/v1/health` that returns:
- Application status
- System information
- Dependency status

#### Logging Configuration

Configure logging levels via environment variables:

```bash
LOG_LEVEL=INFO  # DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_FILE=/var/log/gst-api/app.log
LOG_FORMAT=json  # json or text
```

#### External Monitoring

**Sentry Integration:**
```bash
SENTRY_DSN=your-sentry-dsn
```

**Prometheus Metrics:**
The application exposes metrics at `/metrics` endpoint when enabled:
```bash
METRICS_ENABLED=true
```

### Log Aggregation

#### ELK Stack

1. Configure Filebeat to ship logs
2. Use Logstash for log processing
3. Store in Elasticsearch
4. Visualize with Kibana

#### Cloud Logging

- **AWS CloudWatch**: Automatic log collection in ECS/Lambda
- **Google Cloud Logging**: Built-in for Cloud Run
- **Azure Monitor**: Integrated with App Service

## Security Considerations

### 1. Environment Variables

- Never commit secrets to version control
- Use secure secret management services
- Rotate secrets regularly

### 2. Network Security

- Use HTTPS in production
- Configure proper CORS settings
- Implement rate limiting
- Use Web Application Firewall (WAF)

### 3. Container Security

- Use non-root user in containers
- Scan images for vulnerabilities
- Keep base images updated
- Use minimal base images

### 4. Access Control

- Implement API authentication
- Use least privilege principle
- Monitor access logs
- Set up alerting for suspicious activity

## Troubleshooting

### Common Issues

#### 1. Application Won't Start

```bash
# Check logs
docker logs gst-api
# or
journalctl -u gst-api -f

# Verify environment variables
env | grep FLASK

# Test configuration
python -c "from config import get_config; print(get_config())"
```

#### 2. High Memory Usage

- Monitor session storage
- Implement session cleanup
- Adjust worker processes
- Check for memory leaks

#### 3. Slow Response Times

- Monitor external API calls
- Implement caching
- Optimize database queries
- Scale horizontally

#### 4. Rate Limiting Issues

```bash
# Check rate limit configuration
curl -I http://localhost:5001/api/v1/getCaptcha

# Monitor rate limit headers
# X-RateLimit-Limit
# X-RateLimit-Remaining
# X-RateLimit-Reset
```

### Performance Tuning

#### 1. Gunicorn Configuration

```bash
# Calculate workers: (2 x CPU cores) + 1
workers = 4
worker_class = "sync"
worker_connections = 1000
timeout = 120
keepalive = 2
max_requests = 1000
max_requests_jitter = 100
```

#### 2. Database Optimization

- Use connection pooling
- Implement query caching
- Optimize indexes
- Monitor slow queries

#### 3. Caching Strategy

- Redis for session storage
- CDN for static assets
- Application-level caching
- Database query caching

### Debugging

#### Enable Debug Mode (Development Only)

```bash
FLASK_ENV=development
DEBUG=true
LOG_LEVEL=DEBUG
```

#### Profiling

```python
# Add to app.py for profiling
from werkzeug.middleware.profiler import ProfilerMiddleware

if app.config.get('PROFILING_ENABLED'):
    app.wsgi_app = ProfilerMiddleware(app.wsgi_app)
```

## Support

For deployment issues:

1. Check the [troubleshooting section](#troubleshooting)
2. Review application logs
3. Verify configuration settings
4. Test with minimal configuration
5. Create an issue on GitHub with:
   - Deployment method
   - Error messages
   - Configuration (without secrets)
   - Environment details

---

**Note**: Always test deployments in a staging environment before production deployment. Keep your dependencies updated and monitor security advisories.