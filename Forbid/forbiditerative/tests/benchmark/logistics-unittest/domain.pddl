
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Domain file automatically generated by the Tarski FSTRIPS writer
;;; 
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define (domain logistics-domain)
    (:requirements :equality :action-costs :typing)
    (:types
        locatable - object
        movable - locatable
        vehicle - movable
        location - locatable
        package - movable
        truck - vehicle
        airplane - vehicle
        city - object
        airport - location
        object
    )

    (:constants
        
    )

    (:predicates
        (in-city ?x1 - location ?x2 - city)
        (at ?x1 - movable ?x2 - location)
        (in ?x1 - package ?x2 - vehicle)
    )

    (:functions
        (total-cost ) - number
    )

    

    
    (:action load
     :parameters (?pv - package ?vv - vehicle ?lv - location)
     :precondition (and (at ?vv ?lv) (at ?pv ?lv))
     :effect (and
        (not (at ?pv ?lv))
        (in ?pv ?vv)
        (increase (total-cost ) 1))
    )


    (:action unload
     :parameters (?pv - package ?vv - vehicle ?lv - location)
     :precondition (and (at ?vv ?lv) (in ?pv ?vv))
     :effect (and
        (not (in ?pv ?vv))
        (at ?pv ?lv)
        (increase (total-cost ) 1))
    )


    (:action drive-truck
     :parameters (?tv - truck ?lv - location ?tlv - location ?cv - city)
     :precondition (and (and (at ?tv ?lv) (in-city ?lv ?cv)) (in-city ?tlv ?cv))
     :effect (and
        (not (at ?tv ?lv))
        (at ?tv ?tlv)
        (increase (total-cost ) 1))
    )


    (:action fly-airplane
     :parameters (?av - airplane ?fapv - airport ?tapv - airport)
     :precondition (at ?av ?fapv)
     :effect (and
        (not (at ?av ?fapv))
        (at ?av ?tapv)
        (increase (total-cost ) 1))
    )

)