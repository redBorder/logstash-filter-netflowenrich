# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

# This example filter will replace the contents of the default
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an example.
class LogStash::Filters::Netflowenrich < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  #
  # filter {
  #   example {
  #     message => "My message..."
  #   }
  # }
  #
  config_name "netflowenrich"

  # Replace the message with this value.
  config :message, :validate => :string, :default => "Hello World!"


  public
  def register
    # Add instance variables
  end # def register

  public
  def filter(event)

    #Codigo traducido
    delayed = 15
    now = Time.now.utc
    generatedPackets = []
    if event.include?("first_switched") && event.include?("timestamp") then

      packet_start = event.get("first_switched").to_i #se asume que son segundos desde época unix en UTC
      packet_end = event.get("timestamp").to_i

      now_hour = now.hour
      now_min = now.min

      packet_end_hour = Time.at(event.get("timestamp")).utc.hour # .at() devuelve el tiempo local, necesario volver a representarlo en UTC
      packet_start_hour = Time.at(event.get("first_switched")).utc.hour


      if now_min < delayed then
        an_hour_ago = now - 3600
        limit = Time.utc(an_hour_ago.year, an_hour_ago.month, an_hour_ago.day, an_hour_ago.hour, 0, 0) # hora anterior en punto
      else
        limit = Time.utc(now.year, now.month, now.day, now.hour, 0, 0) # hora actual en punto
      end

      #Desechar eventos muy antiguos
      if ((packet_end_hour == now_hour - 1) && (now_min > delayed)) || 
         (now.to_i - packet_end >  60 * 60) then
        elsif packet_start < limit.to_i
        # code
        packet_start = limit.to_i
        event.set("first_switched", limit.to_i)
      end

      #eventos correctos en el futuro
      if ((packet_end > now.to_i) && (packet_end_hour != packet_start_hour)) ||
         (packet_end - now.to_i  >  60 * 60) then
        event.set("timestamp", now.to_i)
        packet_end = now.to_i
        if !(packet_end > packet_start) then
          event.set("first_switched", now.to_i)
          packet_start = now.to_i
        end
      end
    # -------------------------------------------

      this_end = packet_start
      bytes = 0
      pkts = 0

      if event.include?("bytes") then
        bytes = event.get("bytes").to_i
      end

      if event.include?("pkts") then
        pkts = event.get("pkts").to_i
      end

      totalDiff = packet_end - packet_start;
      bytes_count = 0
      pkts_count = 0
      begin
        this_start = this_end
        this_end = this_start + 60 - Time.at(this_start).utc.sec
        if this_end > packet_end then
          this_end = packet_end
        end
        diff = this_end - this_start

        if (totalDiff == 0) then
          this_bytes = bytes
        else
          this_bytes = (bytes * diff / totalDiff).ceil
        end

        if (totalDiff == 0) then
          this_pkts = pkts
        else
          this_pkts = (pkts * diff / totalDiff).ceil
        end
        bytes_count += this_bytes
        pkts_count += this_pkts

        #crear el evento nuevo para añadir cada termino que ya existia
        to_send = event.clone()
        to_send.set("timestamp", this_start)
        to_send.set("bytes", this_bytes)
        to_send.set("pkts", this_pkts)
        to_send.remove("first_switched")
        generatedPackets.push(to_send)
      end while (this_end < packet_end)

      if (bytes != bytes_count) || (pkts != pkts_count) then
        last_index = generatedPackets.size - 1
        last = generatedPackets[last_index]
        new_pkts = last.get("pkts").to_i + (pkts - pkts_count)
        new_bytes = last.get("bytes").to_i + (bytes - bytes_count)

        if (new_pkts > 0) then
          last.set("pkts", new_pkts)
        end
        if (new_bytes > 0) then
          last.set("bytes", new_bytes)
        end

        generatedPackets[last_index]=last
      end

    elsif event.include?("timestamp") then
      #try
      if event.include?("bytes")
        bytes = event.get("bytes") 
        generatedPackets.push(event)
      else
        return generatedPackets
      end
      #catch
    else
      #try
      if event.include?("bytes")
        bytes = event.get("bytes")
        event.set("bytes", bytes)
        event.set("timestamp", timestamp)
        generatedPackets.push(last)
      else
        return generatedPackets
      end
      #catch
    end
    # We will leave the duration of the message only on the first generated packet
    generatedPackets.each_with_index do |packet,index|
      if index == 0 then next end
      packet.remove("duration")
    end

    #return generatedPackets 
    #esto debe devolver una lista de eventos
    
    generatedPackets.each do |e|
      yield e
    end
    filter_matched(event)
  end  # def filter(event)
end # class LogStash::Filters::Example
