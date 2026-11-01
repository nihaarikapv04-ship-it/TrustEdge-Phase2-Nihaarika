from html.parser import HTMLParser
from pathlib import Path
import re
import tempfile
import unittest
from trustedge.demo import seed_demo
from trustedge.storage import Storage
from trustedge.service import Gateway
from trustedge.policy import SimulationPolicy

class Markup(HTMLParser):
    def __init__(self):
        super().__init__();self.ids=[];self.resources=[]
    def handle_starttag(self,tag,attrs):
        attrs=dict(attrs)
        if 'id' in attrs:self.ids.append(attrs['id'])
        if tag in ('script','link'):
            self.resources.append(attrs.get('src',attrs.get('href','')))

class DashboardAssetTests(unittest.TestCase):
    def test_dom_bindings_are_present_and_assets_are_self_contained(self):
        directory=Path(__file__).parents[1]/'trustedge/static'
        markup=Markup();markup.feed((directory/'index.html').read_text())
        self.assertEqual(len(markup.ids),len(set(markup.ids)))
        js=(directory/'dashboard.js').read_text()
        for identifier in re.findall(r"""\$\(['"]([^'"]+)['"]\)""",js):
            self.assertIn(identifier,markup.ids)
        self.assertEqual(set(markup.resources),{'/dashboard.css','/dashboard.js'})
        for unsafe in ('innerHTML','outerHTML','localStorage','sessionStorage','document.write','eval('):
            self.assertNotIn(unsafe,js)
        for page in ('overview','devices','traffic','trust','topology','audit','system'):
            self.assertIn('view-'+page,markup.ids)

    def test_phase1_palette_and_topology_are_local_accessible_and_animated(self):
        directory=Path(__file__).parents[1]/'trustedge/static'
        css=(directory/'dashboard.css').read_text().lower()
        js=(directory/'dashboard.js').read_text()
        html=(directory/'index.html').read_text()
        for color in ('#0f1117','#1a1d27','#22263a','#534ab7','#22c55e','#f59e0b','#ef4444','#6366f1'):
            self.assertIn(color,css)
        self.assertIn('animateMotion',js)
        self.assertIn('prefers-reduced-motion: reduce',js)
        self.assertIn('topologyPaused',js)
        self.assertIn('topologySignature',js)
        self.assertIn('pauseAnimations',js)
        self.assertIn('!state.data.ready',js)
        self.assertIn('role: "button"',js)
        self.assertIn('group.onkeydown',js)
        self.assertIn('const tier = device.applied_tier',js)
        self.assertIn('tier === "QUARANTINE"',js)
        self.assertIn('pending || !tier',js)
        self.assertIn('not measured packets',html)
        self.assertIn('topology-prev',html)
        self.assertIn('topology-next',html)

    def test_demo_uses_real_simulation_pipeline_and_rejects_live_storage(self):
        store=Storage(':memory:','simulation')
        try:
            g=Gateway(store,SimulationPolicy());seed_demo(g)
            devices=list(store.devices().values())
            self.assertEqual(len(devices),5)
            self.assertEqual(sum(d['applied_tier']=='TRUSTED' for d in devices),3)
            self.assertEqual(sum(d['applied_tier']=='QUARANTINE' for d in devices),1)
            self.assertTrue(store.windows())
            with self.assertRaises(ValueError):seed_demo(g)
        finally:store.close()
        live=Storage(':memory:','live')
        try:
            with self.assertRaises(ValueError):seed_demo(Gateway(live,SimulationPolicy()))
        finally:live.close()
