-- Migrations: 20240801_initial.sql

-- default table for account users
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  created_on datetime DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  updated_on datetime DEFAULT NULL,
  token_created_on datetime DEFAULT NULL,
  email varchar(50) UNIQUE NOT NULL,
  password varchar(60) DEFAULT NULL,
  full_name varchar(50) NOT NULL,
  department_id tinyint unsigned NOT NULL,
  title_id tinyint unsigned NOT NULL,
  role_name varchar(50) DEFAULT NULL,
  salesperson_code varchar(50) DEFAULT NULL,
  salesperson_branch_code varchar(50) DEFAULT NULL,
  token varchar(200) DEFAULT NULL,
  is_enabled tinyint NOT NULL DEFAULT 1
);

-- Create roles table
CREATE TABLE IF NOT EXISTS roles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Create permissions table
CREATE TABLE IF NOT EXISTS permissions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Create role_has_permissions table
CREATE TABLE IF NOT EXISTS role_has_permissions (
    role_id INT NOT NULL,
    permission_id INT NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
);

-- Create user_has_roles table
CREATE TABLE IF NOT EXISTS user_has_roles (
    user_id INT NOT NULL,
    role_id INT NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create user_has_permissions table
CREATE TABLE IF NOT EXISTS user_has_permissions (
    user_id INT NOT NULL,
    permission_id INT NOT NULL,
    PRIMARY KEY (user_id, permission_id),
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);