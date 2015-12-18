# run migrations
set -e

cd ${INSTALLDIR}/${NAME}

${VENV}/bin/python run_migrations.py
${VENV}/bin/python load_fixtures.py
