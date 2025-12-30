#!/bin/bash
gunicorn -w 4 -k uvicorn.workers.UvicornWorker app.main:app --timeout 120 --keep-alive 65
