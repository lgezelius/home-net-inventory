

.PHONY: test cov cov-html

# Run the full test suite

test:
	pytest -q

# Print coverage summary and list missing lines

cov:
	pytest -q --cov=app --cov-report=term-missing

# Generate an HTML coverage report in ./htmlcov/

cov-html:
	pytest -q --cov=app --cov-report=html
	@echo "Open htmlcov/index.html"