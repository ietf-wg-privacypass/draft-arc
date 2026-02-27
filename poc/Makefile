SAGEFILES := $(basename $(notdir $(wildcard *.sage)))
PYFILES := $(addprefix sagelib/, $(addsuffix .py,$(SAGEFILES)))
.PRECIOUS: $(PYFILES)

.PHONY: pyfiles
pyfiles: sagelib/__init__.py $(PYFILES)

sagelib/__init__.py:
	mkdir -p sagelib
	echo pass > sagelib/__init__.py

sagelib/%.py: %.sage
	@echo "Parsing $<"
	@sage --preparse $<
	@mv $<.py $@

# Check Python dependencies
.PHONY: check-deps
check-deps:
	@echo "Checking Python dependencies..."
	@sage -c "import cryptography" 2>/dev/null || \
		(echo ""; \
		 echo "ERROR: Python 'cryptography' module is not installed in Sage's Python."; \
		 echo ""; \
		 echo "To install dependencies, run ONE of the following:"; \
		 echo "  1. Using pip in a virtual environment (recommended):"; \
		 echo "       python3 -m venv venv"; \
		 echo "       source venv/bin/activate"; \
		 echo "       pip install -r requirements.txt"; \
		 echo ""; \
		 echo "  2. Using pip with --user flag:"; \
		 echo "       python3 -m pip install --user 'cryptography>=46.0.5'"; \
		 echo ""; \
		 echo "  3. Using pip with --break-system-packages (not recommended):"; \
		 echo "       python3 -m pip install --break-system-packages 'cryptography>=46.0.5'"; \
		 echo ""; \
		 echo "  4. Install directly in Sage's Python environment:"; \
		 echo "       sage -pip install 'cryptography>=46.0.5'"; \
		 echo ""; \
		 exit 1)
	@echo "✓ All dependencies satisfied"

# Build sigma/poc Python files if needed
setup: check-deps
	@echo "Building sigma/poc Python files..."
	@cd sigma/poc && $(MAKE) clean pyfiles
	@echo "Setup complete"

test: pyfiles setup
	sage test_range_proof.sage
	sage test_arc.sage
	sage test_arc_negative.sage

vectors: pyfiles setup
	@echo "Removing vectors folder, if present"
	@rm -rf vectors
	@echo "Creating vectors folder"
	@mkdir -p vectors
	sage test_arc.sage

.PHONY: clean
clean:
	rm -rf sagelib *.pyc *.sage.py *.log __pycache__

.PHONY: distclean
distclean: clean
	rm -rf vectors ascii