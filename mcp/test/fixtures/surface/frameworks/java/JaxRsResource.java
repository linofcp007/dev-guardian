package com.example;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.POST;

// J10 JAX-RS / Quarkus — a whole framework family the pack does not cover
@Path("/jaxrs/items")
public class JaxRsResource {
    @GET
    public String list() { return "[]"; }

    @POST
    @Path("/{id}")
    public String create() { return "{}"; }
}
