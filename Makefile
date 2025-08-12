# Django GST Verification API - Development Tools

.PHONY: help format lint check test clean install

help:
	@echo "Available commands:"
	@echo "  format    - Format code with black and isort"
	@echo "  lint      - Run flake8 linter"
	@echo "  check     - Run both linting and formatting checks"
	@echo "  test      - Run Django tests"
	@echo "  clean     - Clean Python cache files"
	@echo "  install   - Install development dependencies"
	@echo "  runserver - Start Django development server"

format:
	@echo "Formatting code with black..."
	black .
	@echo "Sorting imports with isort..."
	isort .
	@echo "Code formatting complete!"

lint:
	@echo "Running flake8 linter..."
	flake8 .
	@echo "Linting complete!"

check: lint
	@echo "Checking code formatting..."
	black --check .
	isort --check-only .
	@echo "All checks passed!"

test:
	@echo "Running Django tests..."
	python manage.py test

clean:
	@echo "Cleaning Python cache files..."
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	@echo "Cache files cleaned!"

install:
	@echo "Installing development dependencies..."
	pip install flake8 black isort django-extensions
	@echo "Dependencies installed!"

runserver:
	@echo "Starting Django development server..."
	python manage.py runserver