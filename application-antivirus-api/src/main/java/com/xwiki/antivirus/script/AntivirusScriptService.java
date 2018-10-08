/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package com.xwiki.antivirus.script;

import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.manager.ComponentManager;
import com.xwiki.antivirus.AntivirusConfiguration;
import com.xwiki.antivirus.AntivirusEngine;
import org.xwiki.script.service.ScriptService;

/**
 * Exposing Antivirus API to scripts.
 *
 * @version $Id$
 */
@Component
@Named("antivirus")
@Singleton
public class AntivirusScriptService implements ScriptService
{
    @Inject
    private ComponentManager componentManager;

    @Inject
    private AntivirusConfiguration configuration;

    @Inject
    private Logger logger;

    /**
     * @return the name of the {@link AntivirusEngine} to use when scanning
     */
    public String getDefaultAntivirusName()
    {
        return configuration.getDefaultEngineName();
    }

    /**
     * @return the name of the available {@link AntivirusEngine} implementations that can be used while scanning
     */
    public List<String> getAntivirusNames()
    {
        List<String> names = new ArrayList<>();
        try {
            names = new ArrayList<>(componentManager.getInstanceMap(AntivirusEngine.class).keySet());
        } catch (Exception e) {
            logger.error("Failed to get list of antivirus names", e);
        }

        return names;
    }
}
