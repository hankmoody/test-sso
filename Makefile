VENV = .venv
PYTHON = $(VENV)/bin/python
FLASK = $(VENV)/bin/flask

run: $(VENV) requirements.txt
	$(FLASK) run -h localhost -p 5001

$(VENV):
	python3 -m venv $(VENV)
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -r requirements.txt 

clean:
	rm -rf $(VENV) __pycache__ *.pyc *.pyo

.PHONY: run clean

