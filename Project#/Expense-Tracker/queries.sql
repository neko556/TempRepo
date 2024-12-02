-- Create the database if it doesn't exist
CREATE DATABASE IF NOT EXISTS `tracker`;
USE `tracker`;

-- Drop the users table if it exists
DROP TABLE IF EXISTS `users`;

-- Create the users table
CREATE TABLE `users`
(
  `id` int NOT NULL AUTO_INCREMENT,
  `first_name` varchar(100) DEFAULT NULL,
  `last_name` varchar(100) DEFAULT NULL,
  `email` varchar(100) DEFAULT NULL,
  `username` varchar(100) DEFAULT NULL,
  `password` varchar(100) DEFAULT NULL,
  `role` varchar(100) DEFAULT 'user',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Drop the transactions table if it exists


-- Create the transactions table
CREATE TABLE IF NOT EXISTS `transactions`
(
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int DEFAULT NULL,
  `amount` int NOT NULL DEFAULT '0',
  `description` varchar(255) DEFAULT NULL,
  `category` varchar(255) DEFAULT NULL,
  `date` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY (`user_id`),
  CONSTRAINT `transactions_ibfk_1`
    FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
-- Create user_budget table if it doesn't exist
-- Create user_budget table if it doesn't exist
-- Create user_budget table if it doesn't exist
CREATE TABLE IF NOT EXISTS user_budget (
    user_id INT PRIMARY KEY,
    monthly_budget DECIMAL(10,2) NOT NULL,
    monthly_savings_goal DECIMAL(10,2) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create category_budgets table
CREATE TABLE  IF NOT EXISTS category_budgets (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    category VARCHAR(100) NOT NULL,
    budget_limit DECIMAL(10,2) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_category (user_id, category)
);
-- Add indexes for better query performance
ALTER TABLE transactions ADD INDEX idx_user_date (user_id, date);
ALTER TABLE transactions ADD INDEX idx_category (category);

-- Add foreign key constraints if missing
ALTER TABLE transactions
ADD CONSTRAINT fk_user_id
FOREIGN KEY (user_id) REFERENCES users(id)
ON DELETE CASCADE;

-- Modify user_budget table to ensure proper constraints
ALTER TABLE user_budget
MODIFY monthly_budget DECIMAL(10,2) NOT NULL DEFAULT 0.00,
MODIFY monthly_savings_goal DECIMAL(10,2) NOT NULL DEFAULT 0.00;

-- Modify category_budgets table to ensure proper constraints
ALTER TABLE category_budgets
MODIFY budget_limit DECIMAL(10,2) NOT NULL DEFAULT 0.00,
ADD CONSTRAINT unique_user_category UNIQUE (user_id, category);

-- Add trigger to ensure transaction amounts are properly formatted
DELIMITER //
CREATE TRIGGER before_transaction_insert
BEFORE INSERT ON transactions
FOR EACH ROW
BEGIN
    IF NEW.amount = 0 THEN
        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Transaction amount cannot be zero';
    END IF;
END;//
DELIMITER ;

-- Add view for monthly spending summary
CREATE OR REPLACE VIEW monthly_spending_summary AS
SELECT 
    user_id,
    DATE_FORMAT(date, '%Y-%m') as month,
    category,
    SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END) as income,
    ABS(SUM(CASE WHEN amount < 0 THEN amount ELSE 0 END)) as expenses
FROM transactions
GROUP BY user_id, DATE_FORMAT(date, '%Y-%m'), category;
