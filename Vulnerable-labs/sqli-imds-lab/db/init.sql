-- Runs automatically on first container start (docker-entrypoint-initdb.d).

CREATE EXTENSION IF NOT EXISTS http;

CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    price NUMERIC(10, 2) NOT NULL
);

INSERT INTO products (name, category, price) VALUES
    ('Wireless Mouse', 'electronics', 19.99),
    ('Mechanical Keyboard', 'electronics', 89.99),
    ('The Pragmatic Programmer', 'books', 34.50),
    ('Clean Code', 'books', 29.99),
    ('Building Blocks Set', 'toys', 24.99),
    ('RC Car', 'toys', 49.99);

-- The app connects as this role. It is deliberately over-privileged:
-- EXECUTE on every function in public includes pgsql-http's http()/
-- http_get() functions, which is what makes the SQLi -> IMDS chain
-- possible. A properly locked-down app role would only get SELECT on
-- specific tables and no function grants at all.
CREATE USER appuser WITH PASSWORD 'appuserpassword';
GRANT SELECT ON products TO appuser;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO appuser;
