FROM openresty/openresty:alpine

# lua-resty-http for the cosocket call to the approval API; curl for healthcheck;
# ca-certificates so proxy_ssl / lua_ssl can verify pypi.org + files.pythonhosted.org.
RUN apk add --no-cache curl ca-certificates perl \
    && /usr/local/openresty/bin/opm get ledgetech/lua-resty-http

COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY lua/ /usr/local/openresty/lua/

EXPOSE 8080

HEALTHCHECK --interval=5s --timeout=3s --retries=10 \
  CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1

CMD ["openresty", "-g", "daemon off;"]
