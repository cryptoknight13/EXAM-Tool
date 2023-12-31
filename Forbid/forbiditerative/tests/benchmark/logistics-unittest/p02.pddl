
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Instance file automatically generated by the Tarski FSTRIPS writer
;;; 
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define (problem p02-problem)
    (:domain logistics-domain)

    (:objects
        airplane1 airplane2 - airplane
        airport1 airport2 - airport
        city1 city2 - city
        location1 location2 location3 - location
        package1 package2 package3 package4 package5 package6 package7 package8 - package
        truck1 truck2 - truck
    )

    (:init
        (= (total-cost ) 0.0)
        (at package4 location2)
        (at package6 location2)
        (at package7 location3)
        (at truck2 location2)
        (at package3 location1)
        (at package1 location1)
        (at package2 location2)
        (at package5 location2)
        (at airplane2 airport1)
        (at package8 location3)
        (at airplane1 airport2)
        (at truck1 location1)
        (in-city location1 city1)
        (in-city location2 city2)
        (in-city airport2 city2)
        (in-city location3 city1)
        (in-city airport1 city1)
    )

    (:goal
        (and (at package1 airport1) (at package2 location3) (at package3 airport2) (at package4 location1) (at package5 location1) (at package6 location1) (at package7 location1) (at package8 location1))
    )

    
    
    (:metric minimize (total-cost ))
)

