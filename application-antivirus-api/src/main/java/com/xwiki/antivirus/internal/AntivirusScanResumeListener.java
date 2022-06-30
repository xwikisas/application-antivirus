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
package com.xwiki.antivirus.internal;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.List;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.slf4j.Logger;
import org.xwiki.bridge.event.ApplicationReadyEvent;
import org.xwiki.component.annotation.Component;
import org.xwiki.environment.Environment;
import org.xwiki.observation.AbstractEventListener;
import org.xwiki.observation.event.Event;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.plugin.scheduler.SchedulerPlugin;

/**
 * Detects if an antivirus scan job was interrupted at wiki server restart and resumes it.
 *
 * @version $Id$
 * @since 1.5
 */
@Component
@Named(AntivirusScanResumeListener.ROLE_HINT)
@Singleton
public class AntivirusScanResumeListener extends AbstractEventListener
{
    private static final List<Event> EVENTS = Collections.singletonList(new ApplicationReadyEvent());

    public static final String ROLE_HINT = "AntivirusScanResumeListener";

    @Inject
    Environment environment;

    @Inject
    Provider<XWikiContext> contextProvider;

    @Inject
    private Logger logger;

    public AntivirusScanResumeListener()
    {
        super(ROLE_HINT, EVENTS);
    }

    @Override
    public void onEvent(Event event, Object source, Object data)
    {
        if (Files.exists(
            Paths.get(environment.getPermanentDirectory() + AntivirusJob.PATH + AntivirusJob.JSON_FILE_NAME)))
        {
            logger.debug("Resuming interrupted Antivirus Job.");
            try {
                XWikiContext xcontext = contextProvider.get();

                SchedulerPlugin scheduler =
                    (SchedulerPlugin) xcontext.getWiki().getPluginManager().getPlugin("scheduler");
                XWikiDocument jobDoc = xcontext.getWiki().getDocument(AntivirusJobSchedulerListener.JOB_DOC, xcontext);
                BaseObject job = jobDoc.getXObject(SchedulerPlugin.XWIKI_JOB_CLASSREFERENCE);

                scheduler.triggerJob(job, xcontext);
            } catch (XWikiException e) {
                logger.error("Failed to resume Antivirus Job after detecting interruption at wiki server restart", e);
            }
        }
    }
}
