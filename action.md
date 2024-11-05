## Update Action

Update Pipfile
```bash
PIPENV_IGNORE_VIRTUALENVS=1 pipenv lock
PIPENV_IGNORE_VIRTUALENVS=1 pipenv sync
PIPENV_IGNORE_VIRTUALENVS=1 pipenv run pip freeze > requirements.txt
```