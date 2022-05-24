package com.in28minutes.soap.webservices.soapcoursemanagement.security;

import org.apache.wss4j.common.ext.WSPasswordCallback;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class ClientPasswordCallbackHandler implements CallbackHandler {

    private Map<String, String> users = new HashMap<>();

    public ClientPasswordCallbackHandler() {
        users.put("server", "server-pass");
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (Callback callback : callbacks) {
            if (callback instanceof WSPasswordCallback) {
                WSPasswordCallback pc = (WSPasswordCallback) callback;

                if (users.containsKey(pc.getIdentifier())) {
                    pc.setPassword(users.get(pc.getIdentifier()));
                }
            } else {
                throw new UnsupportedCallbackException(callback, "Unrecognized Callback");
            }
        }
    }
}
