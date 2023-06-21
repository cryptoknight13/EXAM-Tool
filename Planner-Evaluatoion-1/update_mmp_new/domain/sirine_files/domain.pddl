(define (domain domaingotocity)
(:requirements :typing)
(:types city - object)
(:predicates 
    (at ?x - city)
    (has_taxi ?x ?y - city)
    (has_bus ?x ?y - city)
    (neighboring ?x ?y - city)
)
  
  (:action go
    :parameters (?from ?to - city)
    :precondition (and 
      (at ?from) 
      (has_taxi ?from ?to) 
    )
    :effect (and
      (not (at ?from))
      (at ?to)
    )
  )
  (:action go2
    :parameters (?from ?to - city)
    :precondition (and 
      (at ?from) 
      (has_bus ?from ?to)
    )
    :effect (and
      (not (at ?from))
      (at ?to)
    )
  )


)
