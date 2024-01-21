CALL gds.graph.project("tickets", "*", "*");
CALL gds.wcc.write("tickets", {writeProperty: "clusterID"})

