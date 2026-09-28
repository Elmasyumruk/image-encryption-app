@echo off
echo === Image Encryption Application (IEA) ===
echo Installing dependencies...
pip install -r requirements.txt -q
pip install cryptography -q

echo Generating SSL certificate...
python gen_cert.py

echo.
echo Starting HTTPS server...
echo.
echo  Open in browser: https://localhost:5000
echo  Second computer: use the Network URL printed below
echo  NOTE: Browser will warn about self-signed cert - click Advanced, then Proceed
echo.
python app.py
pause
