# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

class LogStash::Filters::Netflowenrich < LogStash::Filters::Base

  config_name "netflowenrich"

  public
  def register
    # Add instance variables
  end # def register

  public
  def filter(event)

    delayed = 15
    current_time = Time.now.utc
    generatedPackets = []

    # add the timestamp if missing in the event
    event.set("timestamp", current_time.to_i) if !event.include?("timestamp")

    # thread 'first_switched' events as a serie of events over time
    if event.include?("first_switched") then

      e_first_switched_timestamp = event.get("first_switched")
      e_timestamp = event.get("timestamp")

      packet_start_time = e_first_switched_timestamp.to_i 
      packet_end_time = e_timestamp.to_i

      packet_end_time_hour = Time.at(e_timestamp).utc.hour 
      packet_start_time_hour = Time.at(e_first_switched_timestamp).utc.hour

      if current_time.min < delayed then
        an_hour_ago = current_time - 3600
        limit = Time.utc(an_hour_ago.year, an_hour_ago.month, an_hour_ago.day, an_hour_ago.hour, 0, 0) # hora anterior en punto
      else
        limit = Time.utc(current_time.year, current_time.month, current_time.day, current_time.hour, 0, 0) # hora actual en punto
      end

      #Desechar eventos muy antiguos
      if ((packet_end_time_hour == current_time.hour - 1) && (current_time.min > delayed)) || 
         (current_time.to_i - packet_end_time >  3600) then
         @logger.error("netflow_enrich : Dropped packet #{event.to_s} because its realtime processor is already shutdown.")
      elsif packet_start_time < limit.to_i
        @logger.error("netflow_enrich : Packet #{event.to_s} first switched was corrected because it overpassed the lower limit (event too old).")
        packet_start_time = limit.to_i
        event.set("first_switched", limit.to_i)
      end

      #eventos correctos en el futuro
      if ((packet_end_time > current_time.to_i) && (packet_end_time_hour != packet_start_hour)) || (packet_end_time - current_time.to_i  >  3600) then
        @logger.error("netflow_enrich : Packet #{event.to_s} ended in a future segment and I modified its last and/or first switched values.")
        event.set("timestamp", current_time.to_i)
        packet_end_time = current_time.to_i
        if !(packet_end_time > packet_start_time) then
          event.set("first_switched", current_time.to_i)
          packet_start_time = current_time.to_i
        end
      end

      this_end = packet_start_time
      bytes = 0
      pkts = 0
      bytes = event.get("bytes").to_i if event.include?("bytes")
      pkts = event.get("pkts").to_i if event.include?("pkts") 

      total_diff_time = packet_end_time - packet_start_time;
      bytes_count = 0
      pkts_count = 0
      begin
        this_start = this_end
        this_end = this_start + 60 - Time.at(this_start).utc.sec
        this_end = packet_end_time if this_end > packet_end_time
        this_diff = this_end - this_start

        if (total_diff_time == 0) then
          this_bytes = bytes 
          this_pkts = pkts
        else
          this_bytes = (bytes * this_diff / total_diff_time).ceil
          this_pkts = (pkts * this_diff / total_diff_time).ceil
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

      end while (this_end < packet_end_time)

      # adjust last event in generatedPackets if there were 'rounding' errors
      if (bytes != bytes_count) || (pkts != pkts_count) then
        last_event = generatedPackets[-1]

        # adapt the bytes and packets values
        new_pkts = last_event.get("pkts").to_i + (pkts - pkts_count)
        new_bytes = last_event.get("bytes").to_i + (bytes - bytes_count)
        last_event.set("pkts", new_pkts) if (new_pkts > 0)
        last_event.set("bytes", new_bytes) if (new_bytes > 0)

        generatedPackets[-1]=last_event
      end
    else
      generatedPackets.push(event)
    end

    # We will leave the duration of the message only on the first generated packet
    generatedPackets.drop(1) do |packet|
      packet.remove("duration")
    end

    #return all events stored in generatedPackets 
    #esto debe devolver una lista de eventos    
    generatedPackets.each do |e|
      yield e
    end
    event.cancel if (generatedPackets.count > 1 or event.include?("first_switched"))

  end  # def filter(event)
end # class LogStash::Filters::Example