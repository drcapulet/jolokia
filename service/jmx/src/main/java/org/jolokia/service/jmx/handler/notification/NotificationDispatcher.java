package org.jolokia.service.jmx.handler.notification;

import java.io.IOException;

import javax.management.*;

import org.jolokia.server.core.request.notification.*;
import org.jolokia.server.core.service.notification.NotificationBackendManager;
import org.jolokia.server.core.util.jmx.MBeanServerAccess;
import org.jolokia.server.core.service.api.JolokiaContext;
import org.json.simple.JSONObject;

/**
 * Dispatcher for notification commands. Commands are dispatcher  to
 * the appropriate command in a {@link NotificationListenerDelegate}.
 *
 * @author roland
 * @since 18.03.13
 */
public class NotificationDispatcher {

    // Delegate for doing the actual registration stuff
    private final NotificationListenerDelegate listenerDelegate;
    private final NotificationBackendManager backendManager;

    /**
     * Initialize backends and delegate
     */
    public NotificationDispatcher(JolokiaContext pContext) {
        backendManager = new NotificationBackendManager(pContext);
        listenerDelegate = new NotificationListenerDelegate(backendManager);
    }

    /**
     * Dispatch a command to the appropriate method in the action in the delegate
     *
     * @param pExecutor executor providing access to the MBeanServers
     * @param pCommand the command to execute
     * @return the result generated by the dispatched actions
     *
     * @throws MBeanException
     * @throws IOException
     * @throws ReflectionException
     */
    public Object dispatch(MBeanServerAccess pExecutor, NotificationCommand pCommand)
            throws MBeanException, IOException, ReflectionException {

        // Shortcut for client used later
        String client = pCommand instanceof ClientCommand ? ((ClientCommand) pCommand).getClient() : null;

        switch (pCommand.getType()) {
            case REGISTER:
                return register();
            case UNREGISTER:
                listenerDelegate.unregister(pExecutor,client);
                return null;
            case ADD:
                return listenerDelegate.addListener(pExecutor, (AddCommand) pCommand);
            case REMOVE:
                listenerDelegate.removeListener(pExecutor, client, ((RemoveCommand) pCommand).getHandle());
                return null;
            case PING:
                listenerDelegate.refresh(client);
                return null;
            case OPEN:
                listenerDelegate.openChannel((OpenCommand) pCommand);
            case LIST:
                return listenerDelegate.list(client);
        }
        throw new UnsupportedOperationException("Unsupported notification command " + pCommand.getType());
    }


    // =======================================================================================


    /**
     * Register a new client and return the client id along with the information
     * of all available backends
     *
     * @return client id with backend configs.
     */
    private JSONObject register()
    {
        String id = listenerDelegate.register();
        JSONObject ret = new JSONObject();
        ret.put("backend",backendManager.getBackendConfig());
        ret.put("id",id);
        return ret;
    }
}
