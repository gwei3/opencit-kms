/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.kms.user.jaxrs;

import com.intel.mtwilson.jaxrs2.NoLinks;
import com.intel.mtwilson.jaxrs2.server.resource.AbstractJsonapiResource;
import com.intel.mtwilson.launcher.ws.ext.V2;
import javax.ws.rs.Path;

/**
 *
 * @author jbuhacoff
 */
@V2
@Path("/users")
public class Users extends AbstractJsonapiResource<User, UserCollection, UserFilterCriteria, NoLinks<User>, UserLocator> {

    private UserRepository repository;

    public Users() {
        repository = new UserRepository();
    }

    @Override
    protected UserCollection createEmptyCollection() {
        return new UserCollection();
    }

    @Override
    protected UserRepository getRepository() {
        return repository;
    }
}
