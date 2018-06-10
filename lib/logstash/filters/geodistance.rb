# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require_relative "elasticsearch/client"
require "logstash/json"
java_import "java.util.concurrent.ConcurrentHashMap"


class LogStash::Filters::GeoDistance < LogStash::Filters::Base
  config_name "geodistance"

  # List of elasticsearch hosts to use for querying.
  config :hosts, :validate => :array,  :default => [ "localhost:9200" ]
  
  # Comma-delimited list of index names to search; use `_all` or empty string to perform the operation on all indices.
  # Field substitution (e.g. `index-name-%{date_field}`) is available
  config :index, :validate => :string, :default => ""

  # Elasticsearch query string. Read the Elasticsearch query string documentation.
  # for more info at: https://www.elastic.co/guide/en/elasticsearch/reference/master/query-dsl-query-string-query.html#query-string-syntax
  config :query, :validate => :string

  # Comma-delimited list of `<field>:<direction>` pairs that define the sort order
  config :sort, :validate => :string, :default => "@timestamp:desc"

  # Basic Auth - username
  config :user, :validate => :string

  # Basic Auth - password
  config :password, :validate => :password

  # SSL
  config :ssl, :validate => :boolean, :default => false

  # SSL Certificate Authority file
  config :ca_file, :validate => :path

  # Whether results should be sorted or not
  config :enable_sort, :validate => :boolean, :default => true

  # How many results to return
  config :result_size, :validate => :number, :default => 1
  
  # What metric system should be used , mph or kmh 
  config :metric_system, :validate => :string, :default => "mph" 

  config :geo_field, :validate => :string, :default => "MLGeo" 
  # Configure speed trigger over geodistance if required   
  config :speed_trigger, :validate => :number, :default => 500 

  # Interval in hours to check for events 
  config :time_interval, :validate => :number, :default => 1 
  
  # Also add geodistance to event 
  config :keep_result, :validate => :boolean, :default => true 
  
  # What tag should the event get if geodistance vs speed threshold is passed 
  config :trigger_tag, :validate => :string, :default => "account_compromised" 
  
  # Tags the event on failure to look up geo information. This can be used in later analysis.
  config :tag_on_failure, :validate => :array, :default => ["_geodistance_failure"]

  attr_reader :clients_pool

  def register
    @clients_pool = java.util.concurrent.ConcurrentHashMap.new

    #Load query if it exists
    if @query_template
      if File.zero?(@query_template)
        raise "template is empty"
      end
      file = File.open(@query_template, "rb")
      @query_dsl = file.read
    end

  end # def register

  def distance loc1, loc2
  rad_per_deg = Math::PI/180  # PI / 180
  rkm = 6371                  # Earth radius in kilometers
  rm = rkm * 1000             # Radius in meters

  dlat_rad = (loc2[0]-loc1[0]) * rad_per_deg  # Delta, converted to rad
  dlon_rad = (loc2[1]-loc1[1]) * rad_per_deg

  lat1_rad, lon1_rad = loc1.map {|i| i * rad_per_deg }
  lat2_rad, lon2_rad = loc2.map {|i| i * rad_per_deg }

  a = Math.sin(dlat_rad/2)**2 + Math.cos(lat1_rad) * Math.cos(lat2_rad) * Math.sin(dlon_rad/2)**2
  c = 2 * Math::atan2(Math::sqrt(a), Math::sqrt(1-a))
  
  multiplier = 1 
  if metric_system == "mph" 
      multiplier = 0.621371 
  end   
  rm * c * multiplier

end
  def filter(event)
    begin
      params = {:index => event.sprintf(@index) }

      if @query_dsl
        query = LogStash::Json.load(event.sprintf(@query_dsl))
        params[:body] = query
      else
        query = event.sprintf(@query)
        params[:q] = query + " AND @timestamp:[now-"+time_interval.to_s+"h TO now]"
        params[:size] = result_size
        params[:sort] =  @sort if @enable_sort
      end

      @logger.debug("Querying elasticsearch for lookup", :params => params)

      results = get_client.search(params)
      raise "Elasticsearch query error: #{results["_shards"]["failures"]}" if results["_shards"].include? "failures"

      resultsHits = results["hits"]["hits"]
      if !resultsHits.nil? && !resultsHits.empty?
          resultsHits.each do |hit|
             geo = hit[geo_field]
	         geo = geo.split(',')
  	         dist = distance(geo_current,geo)
		     if keep_result 
                event.set("geodistance",dist) 
             end 			 
			 deltaTime =  (event.get("@timestamp") - hit["@timestamp"]) / 3600.0  
	         if dist > speed_trigger * deltaTime
	            event.tag(trigger_tag)
		        break
	         end
          end 
      end

    rescue => e
      @logger.warn("Failed to query elasticsearch for previous event", :index => @index, :query => query, :event => event, :error => e)
      @tag_on_failure.each{|tag| event.tag(tag)}
    end
    filter_matched(event) 
  end # def filter

  private
  def client_options
    {
      :ssl => @ssl,
      :hosts => @hosts,
      :ca_file => @ca_file,
      :logger => @logger
    }
  end

  def new_client
    LogStash::Filters::ElasticsearchClient.new(@user, @password, client_options)
  end

  def get_client
    @clients_pool.computeIfAbsent(Thread.current, lambda { |x| new_client })
  end

  # get an array of path elements from a path reference
  def extract_path(path_reference)
    return [path_reference] unless path_reference.start_with?('[') && path_reference.end_with?(']')

    path_reference[1...-1].split('][')
  end

  # given a Hash and an array of path fragments, returns the value at the path
  # @param source [Hash{String=>Object}]
  # @param path [Array{String}]
  # @return [Object]
  def extract_value(source, path)
    path.reduce(source) do |memo, old_key_fragment|
      break unless memo.include?(old_key_fragment)
      memo[old_key_fragment]
    end
  end
end #class LogStash::Filters::Elasticsearch
