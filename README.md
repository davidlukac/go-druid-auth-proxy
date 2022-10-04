# JDBC-BasicAuth Proxy
Simple authentication proxy implemented for usecase of Trino-Druid integration, but works for anything sending
basic-auth credentials as DB credentials. The DB credentials are parsed from body, cached for future requests and 
supplied as basic-auth credentials for each connection.
