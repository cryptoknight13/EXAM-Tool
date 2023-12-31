
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Domain file automatically generated by the Tarski FSTRIPS writer
;;; 
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define (domain miconic-domain)
    (:requirements :equality :action-costs :typing)
    (:types
        passenger - object
        floor - object
        elevator - object
        object
    )

    (:constants
        
    )

    (:predicates
        (ORIGIN ?x1 - passenger ?x2 - floor)
        (DESTINATION ?x1 - passenger ?x2 - floor)
        (ABOVE ?x1 - floor ?x2 - floor)
        (boarded ?x1 - passenger ?x2 - elevator)
        (served ?x1 - passenger)
        (at ?x1 - elevator ?x2 - floor)
    )

    (:functions
        (total-cost ) - number
    )

    

    
    (:action up
     :parameters (?e - elevator ?f1 - floor ?f2 - floor)
     :precondition (and (at ?e ?f1) (ABOVE ?f1 ?f2))
     :effect (and
        (not (at ?e ?f1))
        (at ?e ?f2)
        (increase (total-cost ) 1))
    )


    (:action down
     :parameters (?e - elevator ?f1 - floor ?f2 - floor)
     :precondition (and (at ?e ?f1) (ABOVE ?f2 ?f1))
     :effect (and
        (not (at ?e ?f1))
        (at ?e ?f2)
        (increase (total-cost ) 1))
    )


    (:action board
     :parameters (?f1 - floor ?p - passenger ?e - elevator)
     :precondition (and (at ?e ?f1) (ORIGIN ?p ?f1))
     :effect (and
        (boarded ?p ?e)
        (increase (total-cost ) 0))
    )


    (:action depart
     :parameters (?f1 - floor ?p - passenger ?e - elevator)
     :precondition (and (and (at ?e ?f1) (DESTINATION ?p ?f1)) (boarded ?p ?e))
     :effect (and
        (not (boarded ?p ?e))
        (served ?p)
        (increase (total-cost ) 0))
    )

)