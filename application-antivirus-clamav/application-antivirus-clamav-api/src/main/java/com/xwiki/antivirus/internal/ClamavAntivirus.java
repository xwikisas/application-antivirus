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

import java.io.InputStream;
import java.util.Collections;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.configuration.ConfigurationSource;
import com.xwiki.antivirus.AntivirusEngine;
import com.xwiki.antivirus.AntivirusException;
import com.xwiki.antivirus.ScanResult;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.doc.XWikiAttachment;

import xyz.capybara.clamav.ClamavClient;

/**
 * {@link AntivirusEngine} implementation using a Clamav server.
 *
 * @version $Id$
 */
@Component
@Named("clamav")
@Singleton
public class ClamavAntivirus implements AntivirusEngine
{
    @Inject
    private Provider<XWikiContext> contextProvider;

    @Inject
    @Named("antivirus-clamav")
    private ConfigurationSource configuration;

    @Override
    public ScanResult scan(XWikiAttachment attachment) throws AntivirusException
    {
        // Read the current values from the configuration.
        String host = configuration.getProperty("host", "localhost");
        int port = configuration.getProperty("port", 3310);

        // Initialize the client.
        ClamavClient client = new ClamavClient(host, port);

        // Scan the attachment.
        xyz.capybara.clamav.commands.scan.result.ScanResult clamavResult = null;
        try (InputStream dataStream = attachment.getContentInputStream(contextProvider.get())) {
            clamavResult = client.scan(dataStream);
        } catch (Exception e) {
            throw new AntivirusException(String.format("Failed to scan attachment [%s]", attachment.getReference()), e);
        }

        // Check the results.
        ScanResult result = null;
        if (clamavResult instanceof xyz.capybara.clamav.commands.scan.result.ScanResult.OK) {
            result = new ScanResult(attachment.getReference(), true, Collections.<String>emptyList());
        } else {
            result = new ScanResult(attachment.getReference(), false,
                ((xyz.capybara.clamav.commands.scan.result.ScanResult.VirusFound) clamavResult).getFoundViruses()
                    .values().iterator().next());
        }

        return result;
    }
}
