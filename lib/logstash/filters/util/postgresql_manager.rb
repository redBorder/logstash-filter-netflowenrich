# encoding: utf-8
require "time"
require "dalli"
require "yaml"
require "pg"
require "logstash/util/loggable"

require_relative "location_constant"

class PostgresqlManager
  include LocationConstant
  attr_accessor :enrich_columns, :wlc_sql_store, :store_sensor_sql, 
                :conn, :enrich_columns, :last_update, :memcached,
                :stores_to_update, :database_name, :user, :password, :port, :host

  include LogStash::Util::Loggable

  def initialize(memcached, database_name, user, password, port, host)
     @memcached = memcached
     @enrich_columns = ["campus", "building", "floor", "deployment",
                           "namespace", "market", "organization", "service_provider", 
                           "zone", "campus_uuid", "building_uuid", "floor_uuid", 
                           "deployment_uuid", "namespace_uuid", "market_uuid", "organization_uuid", 
                           "service_provider_uuid", "zone_uuid"]
     @wlc_sql_store = @memcached.get(WLC_PSQL_STORE) || {}
     @sensor_sql_store = @memcached.get(SENSOR_PSQL_STORE) || {}
     @stores_to_update = [WLC_PSQL_STORE, SENSOR_PSQL_STORE]
     @database_name = database_name
     @user = user
     @password = password.empty? ? get_dbpass_from_config_file : password
     @port = port
     @host = host
     @conn = open_db
     @last_update = Time.now
     update(true)
     #updateSalts
  end

  def open_db
    conninfo = "host=#{@host} port=#{@port} dbname=#{@database_name} user=#{@user} password=#{@password}"
    begin
      conn = PG.connect(conninfo)
      conn.set_notice_processor do |message|
        logger.debug? && logger.debug(( description + ':' + message ))
      end
    rescue => err
      logger.error("%p during test setup: %s" % [ err.class, err.message ])
      logger.error("Error connection database.")
      logger.error(*err.backtrace)
    end
    return conn
  end

  def get_dbpass_from_config_file
   pass = ""
   if File.exist?("/opt/rb/var/www/rb-rails/config/database.yml")
         production_config = YAML.load_file("/opt/rb/var/www/rb-rails/config/database.yml")      
         pass = production_config["production"]["password"]
   end
   return pass
  end

  def update(force = false)
    return unless force || need_update?
    puts ">>>>>>>>>>>>>>>>>> UPDATING"
    @last_update = Time.now
    #@conn = open_db 
    @wlc_sql_store = @memcached.get(WLC_PSQL_STORE) || {}
    @sensor_sql_store = @memcached.get(SENSOR_PSQL_STORE) || {}
    @stores_to_update.each { |store_name| update_store(store_name) }
    puts "<<<<<<<<<<<<<<<<<<< UPDATED"
    #@conn.finish if @conn
  end

  def need_update?
    (Time.now - @last_update) > (5*60)
  end

  def save_store(store_name)
    return @memcached.set(WLC_PSQL_STORE,@wlc_sql_store) if store_name == WLC_PSQL_STORE
    return @memcached.set(SENSOR_PSQL_STORE, @sensor_sql_store) if store_name == SENSOR_PSQL_STORE
  end

  def string_is_number?(param)
    true if Float(param) rescue false
  end

  def enrich_client_latlong(latitude,longitude)
    location = {}
    if latitude && longitude && string_is_number?(latitude) && string_is_number?(longitude)
      longitude_dbl = Float((Float(longitude) * 100000) / 100000)
      latitude_dbl = Float((Float(latitude) * 100000) / 100000)
      location["client_latlong"] = "%.6f," % latitude_dbl + "%.6f" % longitude_dbl
    end
    return location
  end
  
  def enrich_with_columns(param)
    enriching = {}
    @enrich_columns.each { |column_name|  enriching[column_name] = param[column_name] if param[column_name] }
    return enriching
  end

  def update_store(store_name)
    begin 
      result = @conn.exec(get_sql_query(store_name))
    rescue
      logger.error("SQL Exception: Error making query")
      @conn.finish if @conn
      @conn = open_db 
      return 
    end
    if result
      tmpCache = Hash.new
      key = "mac_address" if store_name == WLC_PSQL_STORE
      key = "uuid" if store_name == SENSOR_PSQL_STORE
      result.each do |rs| 
        location = {}
        location.merge!rs["enrichment"] if store_name == WLC_PSQL_STORE && rs["enrichment"]
        location.merge!(enrich_client_latlong(rs["latitude"], rs["longitude"]))
        location.merge!(enrich_with_columns(rs)) if store_name == WLC_PSQL_STORE
        if rs[key] && !location.empty?
          tmpCache[rs[key]] = location
          @wlc_sql_store[rs[key]] = location if store_name == WLC_PSQL_STORE
          @sensor_sql_store[rs[key]] = location if store_name == SENSOR_PSQL_STORE
        end
      end
      @wlc_sql_store.reject!{ |k,v| !tmpCache.key?k } if store_name == WLC_PSQL_STORE
      @sensor_sql_store.reject!{ |k,v| !tmpCache.key?k } if store_name == SENSOR_PSQL_STORE
      save_store(store_name)         
    end
  end

  def get_sql_query(store_name)
     return "SELECT uuid, latitude, longitude FROM sensors" if store_name == SENSOR_PSQL_STORE
     return ("SELECT DISTINCT ON (access_points.mac_address) access_points.ip_address, access_points.mac_address, access_points.enrichment," +
            " zones.name AS zone, zones.id AS zone_uuid, access_points.latitude AS latitude, access_points.longitude AS longitude, floors.name AS floor, " +
            " floors.uuid AS floor_uuid, buildings.name AS building, buildings.uuid AS building_uuid, campuses.name AS campus, campuses.uuid AS campus_uuid," +
            " deployments.name AS deployment, deployments.uuid AS deployment_uuid, namespaces.name AS namespace, namespaces.uuid AS namespace_uuid," +
            " markets.name AS market, markets.uuid AS market_uuid, organizations.name AS organization, organizations.uuid AS organization_uuid," +
            " service_providers.name AS service_provider, service_providers.uuid AS service_provider_uuid" +
            " FROM access_points JOIN sensors ON (access_points.sensor_id = sensors.id)" +
            " LEFT JOIN access_points_zones AS zones_ids ON access_points.id = zones_ids.access_point_id" +
            " LEFT JOIN zones ON zones_ids.zone_id = zones.id" +
            " LEFT JOIN (SELECT * FROM sensors WHERE domain_type=101) AS floors ON floors.lft <= sensors.lft AND floors.rgt >= sensors.rgt" +
            " LEFT JOIN (SELECT * FROM sensors WHERE domain_type=5) AS buildings ON buildings.lft <= sensors.lft AND buildings.rgt >= sensors.rgt" +
            " LEFT JOIN (SELECT * FROM sensors WHERE domain_type=4) AS campuses ON campuses.lft <= sensors.lft AND campuses.rgt >= sensors.rgt" +
            " LEFT JOIN (SELECT * FROM sensors WHERE domain_type=7) AS deployments ON deployments.lft <= sensors.lft AND deployments.rgt >= sensors.rgt" +
            " LEFT JOIN (SELECT * FROM sensors WHERE domain_type=8) AS namespaces ON namespaces.lft <= sensors.lft AND namespaces.rgt >= sensors.rgt" +
            " LEFT JOIN (SELECT * FROM sensors WHERE domain_type=3) AS markets ON markets.lft <= sensors.lft AND markets.rgt >= sensors.rgt" +
            " LEFT JOIN (SELECT * FROM sensors WHERE domain_type=2) AS organizations ON organizations.lft <= sensors.lft AND organizations.rgt >= sensors.rgt" +
            " LEFT JOIN (SELECT * FROM sensors WHERE domain_type=6) AS service_providers ON service_providers.lft <= sensors.lft AND service_providers.rgt >= sensors.rgt") if store_name == WLC_PSQL_STORE
  end # end def getSql
end
