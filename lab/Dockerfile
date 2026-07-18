FROM php:8.2-apache

# Install required PHP extensions and tools
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        mariadb-client \
        less \
        unzip \
        curl \
        ca-certificates \
        sudo \
    ; \
    docker-php-ext-install -j "$(nproc)" \
        mysqli \
        pdo \
        pdo_mysql \
        zip \
    ; \
    rm -rf /var/lib/apt/lists/*

# Install WP-CLI
RUN curl -fsSL -o /usr/local/bin/wp https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar; \
    chmod +x /usr/local/bin/wp

# Enable Apache modules
RUN a2enmod rewrite headers

# Add custom PHP configuration
RUN { \
    echo 'upload_max_filesize = 64M'; \
    echo 'post_max_size = 64M'; \
    echo 'memory_limit = 256M'; \
    echo 'max_execution_time = 300'; \
    echo 'max_input_time = 300'; \
    echo 'date.timezone = UTC'; \
} > /usr/local/etc/php/conf.d/wordpress.ini

# WordPress version to download (build arg)
ARG WP_VERSION=7.0.1
ARG WP_URL=https://wordpress.org/wordpress-${WP_VERSION}.zip

# Download and extract WordPress
RUN set -eux; \
    curl -fsSL -o /tmp/wordpress.zip "${WP_URL}"; \
    unzip -q /tmp/wordpress.zip -d /tmp/wp-extract; \
    rm /tmp/wordpress.zip; \
    mkdir -p /var/www/html; \
    cp -r /tmp/wp-extract/wordpress/* /var/www/html/; \
    rm -rf /tmp/wp-extract; \
    chown -R www-data:www-data /var/www/html; \
    mkdir -p /var/www/html/wp-content/plugins; \
    chmod 755 /var/www/html/wp-content /var/www/html/wp-content/plugins

# Configure Apache
RUN sed -i 's/AllowOverride None/AllowOverride All/' /etc/apache2/apache2.conf
ENV APACHE_DOCUMENT_ROOT=/var/www/html
RUN sed -ri -e "s!/var/www/html!${APACHE_DOCUMENT_ROOT}!" /etc/apache2/sites-available/*.conf
RUN sed -ri -e "s!/var/www/!${APACHE_DOCUMENT_ROOT}/..!" /etc/apache2/apache2.conf /etc/apache2/conf-available/*.conf 2>/dev/null; exit 0

WORKDIR /var/www/html

# Copy setup script
COPY setup-wp.sh /usr/local/bin/setup-wp.sh
RUN chmod +x /usr/local/bin/setup-wp.sh
