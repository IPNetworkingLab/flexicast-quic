import numpy as np


COLORS = ["#d7191c", "#fdae61", "#2b83ba", "#abd9e9", "#abdda4", "#999999"]
COLORS_GREY = ["dimgray", "silver", "white"]
COLORS_BLACK_WHITE = ["black", "dimgray", "silver", "white"]
COLORS_SEQUENTIAL_5 = ["#253494", "#2c7fb8", "#41b6c4", "#a1dab4", "#ffffcc"]
COLORS_SEQUENTIAL_4 = ["#253494", "#2c7fb8", "#a1dab4", "#ffffcc"]
COLORS_SEQUENTIAL_3 = ["#253494", "#41b6c4", "#ffffcc"]
COLORS_SEQUENTIAL_2 = ["#2c7fb8", "#ffffcc"]
MARKERS = ["d", "s", "D", "v", "P", "*", "^"]
LINESTYLES = ["solid", (0, (1, 1)), "dashed", "dashdot", (5, (10, 3)), (0, (3, 1, 1, 1))]
LINEWIDTH = 3
MARKERSIZE = 8
HANDLETEXTPAD = 0.2
HANDLELENGTH = 2.5
FIG_HEIGHT = 3.5


def latexify(fig_width=None, fig_height=None, columns=2, nb_subplots_line=1):
    """Set up matplotlib's RC params for LaTeX plotting.
    Call this before plotting a figure.
    Parameters
    ----------
    fig_width : float, optional, inches
    fig_height : float,  optional, inches
    columns : {1, 2}
    """

    # code adapted from http://www.scipy.org/Cookbook/Matplotlib/LaTeX_Examples
    # also adapted from http://bkanuka.com/posts/native-latex-plots/

    # Width and max height in inches for IEEE journals taken from
    # computer.org/cms/Computer.org/Journal%20templates/transactions_art_guide.pdf

    from math import sqrt
    import matplotlib

    assert(columns in [1, 2])

    if fig_width is None:
        # Get this from LaTeX using \the\textwidth
        fig_width_pt = 516
        inches_per_pt = 1.0 / 72.27                      # Convert pt to inch
        scale = 3.39 / 6.9 if columns == 1 else 1
        fig_width = fig_width_pt * inches_per_pt * scale  # width in inches
        # fig_width = 3.39 if columns==1 else 6.9 # width in inches

    if fig_height is None:
        golden_mean = (sqrt(5)-1.0)/2.0    # Aesthetic ratio
        fig_height = fig_width*golden_mean  # height in inches

    fig_width *= nb_subplots_line

    MAX_HEIGHT_INCHES = 8.0
    if fig_height > MAX_HEIGHT_INCHES:
        print("WARNING: fig_height too large {}: so will reduce to {} inches.".format(
            fig_height, MAX_HEIGHT_INCHES))
        fig_height = MAX_HEIGHT_INCHES
    print(fig_width, fig_height)
    font_size = 15
    params = {'backend': 'ps',
              'text.latex.preamble': r'\usepackage[T1]{fontenc} \usepackage{gensymb}',
              'axes.labelsize': font_size + 5,  # fontsize for x and y labels (was 10)
              'axes.titlesize': font_size,
              'font.size': font_size,  # was 10
              'legend.fontsize': font_size,  # was 10
              'xtick.labelsize': font_size,
              'ytick.labelsize': font_size,
              'text.usetex': True,
              'figure.figsize': [fig_width, fig_height],
              'pgf.texsystem': 'pdflatex',
              'grid.alpha': 0.25,
              'mathtext.default': 'regular',  # Don't italize math text
              'font.family': 'serif'
              }

    matplotlib.rcParams.update(params)


def compute_cdf(values, nb_bins: int = 200, add_zero: bool = False):
    hist, bin_edges = np.histogram(values, bins=nb_bins, range=(
        min(values), max(values)), density=True)
    dx = bin_edges[1] - bin_edges[0]
    cdf = np.cumsum(hist) * dx
    if add_zero:
        cdf = np.insert(cdf, 0, 0)
        return bin_edges, cdf
    return bin_edges[1:], cdf