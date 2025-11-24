FROM nginx:alpine

# Copy custom config
COPY ./nginx/nginx.conf /etc/nginx/conf.d/default.conf
