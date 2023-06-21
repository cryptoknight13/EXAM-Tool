
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Instance file automatically generated by the Tarski FSTRIPS writer
;;; 
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define (problem p01-problem)
    (:domain miconic-domain)

    (:objects
        elevator1 elevator2 - elevator
        floor1 floor2 floor3 floor4 - floor
        passenger1 passenger2 passenger3 passenger4 passenger5 passenger6 - passenger
    )

    (:init
        (= (total-cost ) 0.0)
        (ABOVE floor2 floor3)
        (ABOVE floor3 floor4)
        (ABOVE floor1 floor2)
        (ORIGIN passenger2 floor4)
        (ORIGIN passenger5 floor1)
        (ORIGIN passenger4 floor1)
        (ORIGIN passenger1 floor1)
        (ORIGIN passenger6 floor3)
        (ORIGIN passenger3 floor3)
        (DESTINATION passenger4 floor3)
        (DESTINATION passenger2 floor2)
        (DESTINATION passenger3 floor4)
        (DESTINATION passenger6 floor1)
        (DESTINATION passenger5 floor2)
        (DESTINATION passenger1 floor4)
        (at elevator2 floor4)
        (at elevator1 floor1)
    )

    (:goal
        (and (served passenger1) (served passenger2) (served passenger3) (served passenger4) (served passenger5) (served passenger6))
    )

    
    
    (:metric minimize (total-cost ))
)

