-- Placeholder init script
SELECT 1;

-- ────────────────────────────────────────────
-- PGMiner 시나리오용 더미 사용자 데이터
-- ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS leaked_users (
    id            SERIAL PRIMARY KEY,
    username      VARCHAR(50)  NOT NULL,
    email         VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    phone         VARCHAR(20),
    role          VARCHAR(20)  DEFAULT 'user',
    created_at    TIMESTAMP    DEFAULT NOW()
);

INSERT INTO leaked_users (username, email, password_hash, phone, role) VALUES
('admin',       'admin@leafy-corp.com',       '$2b$12$xK9mP3nQ7rS1tU2vW3xY4zA5bC6dE7fG8hI9jK0lM1', '010-0000-0001', 'admin'),
('kim_junho',   'junho.kim@leafy-corp.com',   '$2b$12$aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3aA', '010-1234-5678', 'user'),
('lee_soyeon',  'soyeon.lee@leafy-corp.com',  '$2b$12$bC2dE3fG4hI5jK6lM7nO8pQ9rS0tU1vW2xY3zA4bB', '010-2345-6789', 'user'),
('park_minjae', 'minjae.park@leafy-corp.com', '$2b$12$cD3eF4gH5iJ6kL7mN8oP9qR0sT1uV2wX3yZ4aB5cC', '010-3456-7890', 'user'),
('choi_yuna',   'yuna.choi@leafy-corp.com',   '$2b$12$dE4fG5hI6jK7lM8nO9pQ0rS1tU2vW3xY4zA5bC6dD', '010-4567-8901', 'user'),
('jung_minho',  'minho.jung@leafy-corp.com',  '$2b$12$eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5aB6cD7eE', '010-5678-9012', 'user'),
('han_jiwon',   'jiwon.han@leafy-corp.com',   '$2b$12$fG6hI7jK8lM9nO0pQ1rS2tU3vW4xY5zA6bC7dE8fF', '010-6789-0123', 'user'),
('yoon_gichan', 'gichan.yoon@leafy-corp.com', '$2b$12$gH7iJ8kL9mN0oP1qR2sT3uV4wX5yZ6aB7cD8eF9gG', '010-7890-1234', 'manager'),
('oh_seungho',  'seungho.oh@leafy-corp.com',  '$2b$12$hI8jK9lM0nO1pQ2rS3tU4vW5xY6zA7bC8dE9fG0hH', '010-8901-2345', 'user'),
('shin_eunji',  'eunji.shin@leafy-corp.com',  '$2b$12$iJ9kL0mN1oP2qR3sT4uV5wX6yZ7aB8cD9eF0gH1iI', '010-9012-3456', 'user')
ON CONFLICT (email) DO NOTHING;
