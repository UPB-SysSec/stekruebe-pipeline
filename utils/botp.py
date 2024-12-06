from collections import Counter
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning, MarkupResemblesLocatorWarning
import warnings

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)


class BagOfTreePaths:
    def __init__(self, html_content):
        self.soup = BeautifulSoup(html_content, "html.parser")
        self.paths = self.extract_paths()

    def extract_paths(self):
        """Extract all root-to-leaf paths from the HTML document."""
        paths = []

        def traverse(node, path):
            if not node:
                return
            if node.name:
                path.append(node.name)
            if not node.findChildren():
                paths.append("/".join(path))
            for child in node.findChildren(recursive=False):
                traverse(child, path.copy())

        # Start from the root (usually the <body> tag in an HTML document)
        traverse(self.soup.html, [])
        return Counter(paths)  # A multiset (bag) of paths

    def similarity(self, other_botp, frequencies=False):
        """Compute the similarity between two Bag of Tree Paths using a normalized Jaccard Index."""
        # follows the implementation from the paper which does not use the frequencies, but is still pretty good
        # length of the intersection of the two bags (same as summing minimums for binary indicator as frequencies)
        if frequencies:
            intersection = sum((self.paths & other_botp.paths).values())
            union = sum((self.paths | other_botp.paths).values())
        else:
            intersection = len((self.paths & other_botp.paths).values())
            union = len((self.paths | other_botp.paths).values())

        return intersection / union if union > 0 else 0


class BagOfXPaths:
    def __init__(self, html_content):
        self.soup = BeautifulSoup(html_content, "html.parser")
        self.paths = self.extract_xpaths()

    def extract_xpaths(self):
        """Extract all XPaths from the HTML document."""
        xpaths = []

        def get_xpath(element):
            """Recursively build the XPath for an element."""
            if element.name is None:
                return ""  # Skip non-element nodes like text

            xpath = element.name
            # If the element has siblings of the same type, add an index
            siblings = element.find_previous_siblings(element.name)
            if siblings:
                xpath += f"[{len(siblings) + 1}]"
            return xpath

        def traverse(node, path):
            # Build the XPath for the current node
            if not node:
                return
            xpath = get_xpath(node)
            if xpath:
                path.append(xpath)

            # If leaf node (no children), add the path to the list
            if not node.findChildren():
                xpaths.append("/".join(path))

            # Traverse children recursively
            for child in node.findChildren(recursive=False):
                traverse(child, path.copy())

        # Start from the root element (usually <html>)
        traverse(self.soup.body, [])
        return Counter(xpaths)  # A multiset (bag) of XPaths

    def similarity(self, other_boxp, frequencies=False):
        """Compute similarity between two Bag of XPaths using normalized Jaccard index."""
        if frequencies:
            intersection = sum((self.paths & other_boxp.paths).values())
            union = sum((self.paths | other_boxp.paths).values())
        else:
            intersection = len((self.paths & other_boxp.paths).values())
            union = len((self.paths | other_boxp.paths).values())

        return intersection / union if union > 0 else 0


class BagOfGeneralizedXPaths:
    def __init__(self, html_content):
        self.soup = BeautifulSoup(html_content, "html.parser")
        self.paths = self.extract_generalized_xpaths()

    def extract_generalized_xpaths(self):
        """Extract all generalized XPaths from the HTML document."""
        xpaths = []

        def get_xpath(element):
            """Recursively build the generalized XPath for an element."""
            if element.name is None:
                return ""
