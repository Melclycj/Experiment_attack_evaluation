---- MODULE Smoke ----
EXTENDS Naturals
VARIABLES uidHolder, rowClosed, nsEmpty
Init == uidHolder = "E1" /\ rowClosed = FALSE /\ nsEmpty = FALSE
CloseRow == rowClosed = FALSE /\ rowClosed' = TRUE /\ UNCHANGED <<uidHolder, nsEmpty>>
Reap == nsEmpty = FALSE /\ nsEmpty' = TRUE /\ UNCHANGED <<uidHolder, rowClosed>>
Reclaim == rowClosed /\ nsEmpty /\ uidHolder' = "E2" /\ UNCHANGED <<rowClosed, nsEmpty>>
BadReclaim == nsEmpty /\ uidHolder' = "E2" /\ UNCHANGED <<rowClosed, nsEmpty>>
Next == CloseRow \/ Reap \/ Reclaim
NextBad == CloseRow \/ Reap \/ BadReclaim
Inv == (uidHolder = "E2") => (rowClosed /\ nsEmpty)
====
