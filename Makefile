.PHONY: deps test build deploy delete scan demo

deps:
	pip install -r requirements.txt

test:
	pytest -q --cov=scanner --cov-report=term-missing

scan:
	bash scripts/scan_image.sh images.txt grype cyclonedx-json && \
	python -m scanner --collect reports --fail-on HIGH --out reports/summary.json

build:
	sam build

deploy:
	sam deploy --guided --stack-name sbom-sentinel --capabilities CAPABILITY_IAM

delete:
	sam delete --stack-name sbom-sentinel

demo:
	bash scripts/demo_vuln_image.sh
