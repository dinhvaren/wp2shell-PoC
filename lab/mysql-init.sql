-- MySQL initialization for wp2shell local lab
-- This script runs on first container start only

-- Ensure wordpress user has required privileges
ALTER USER 'wordpress'@'%' IDENTIFIED WITH mysql_native_password BY 'wp2shell_local_only';
GRANT ALL PRIVILEGES ON wordpress.* TO 'wordpress'@'%';
FLUSH PRIVILEGES;
