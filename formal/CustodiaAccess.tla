---- MODULE CustodiaAccess ----
EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS Clients, Secrets, Versions

VARIABLES activeClients, access

AccessKey == [client: Clients, secret: Secrets, version: Versions]

Init == /\ activeClients = Clients
        /\ access = {}

Grant(c, s, v) == /\ c \in activeClients
                  /\ access' = access \union {[client |-> c, secret |-> s, version |-> v]}
                  /\ UNCHANGED activeClients

RevokeRead(c, s, v) == /\ access' = access \ { [client |-> c, secret |-> s, version |-> v] }
                       /\ UNCHANGED activeClients

RevokeClient(c) == /\ activeClients' = activeClients \ {c}
                   /\ access' = {k \in access: k.client # c}

StrongRevokeSecret(s, activeVersion) ==
  /\ access' = {k \in access: k.secret # s \/ k.version = activeVersion}
  /\ UNCHANGED activeClients

Next ==
  \/ \E c \in Clients, s \in Secrets, v \in Versions: Grant(c, s, v)
  \/ \E c \in Clients, s \in Secrets, v \in Versions: RevokeRead(c, s, v)
  \/ \E c \in Clients: RevokeClient(c)
  \/ \E s \in Secrets, v \in Versions: StrongRevokeSecret(s, v)

NoRevokedClientHasAccess == \A k \in access: k.client \in activeClients
PositiveVersionsOnly == \A k \in access: k.version \in Versions

Spec == Init /\ [][Next]_<<activeClients, access>>
====
