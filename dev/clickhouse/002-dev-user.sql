CREATE USER IF NOT EXISTS xshield
IDENTIFIED WITH plaintext_password BY 'xshield_dev';

GRANT ALL ON xshield.* TO xshield;
