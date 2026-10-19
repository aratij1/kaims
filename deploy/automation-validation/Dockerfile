FROM kaims-api-gateway:latest
COPY replacement/kaims_next /app/kaims_next
COPY deploy/automation-validation/runbook.txt /qualification-documents/runbook.txt
WORKDIR /app
CMD ["uvicorn", "kaims_next.runtime:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
