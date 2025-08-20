<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<addon id="plugin.video.czsk.provider"
       name="CZSK Provider"
       version="1.0.1"
       provider-name="Vy">
  <requires>
    <import addon="xbmc.python" version="2.25.0"/>
    <import addon="script.module.requests"/>
  </requires>
  <extension point="xbmc.python.pluginsource"
             library="addon.py">
    <provides>video</provides>
  </extension>
  <extension point="xbmc.addon.metadata">
    <summary lang="cs_CZ">Klient pro soukromý CZSK doplněk.</summary>
    <description lang="cs_CZ">Tento doplněk se připojuje k vašemu soukromému serveru pro Stremio a získává streamy. V nastavení je potřeba zadat Token a MAC adresu zařízení z vaší administrace.</description>
    <summary lang="en_GB">Client for private CZSK addon.</summary>
    <description lang="en_GB">This addon connects to your private Stremio addon server to fetch streams. You need a Token and a Device MAC from your admin panel.</description>
    <platform>all</platform>
    <license>Private</license>
  </extension>
  
  <extension point="xbmc.ui.settings">
    <settings>
      <setting label="API Přihlašovací údaje" type="lsep" />
      <setting id="token" type="text" label="API Token" default=""/>
      <setting id="device_mac" type="text" label="MAC adresa zařízení" default=""/>
    </settings>
  </extension>
</addon>
