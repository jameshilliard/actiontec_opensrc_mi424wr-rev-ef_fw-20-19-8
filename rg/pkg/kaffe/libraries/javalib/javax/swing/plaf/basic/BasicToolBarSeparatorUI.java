/* BasicToolBarSeparatorUI.java --
   Copyright (C) 2004 Free Software Foundation, Inc.

This file is part of GNU Classpath.

GNU Classpath is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

GNU Classpath is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Classpath; see the file COPYING.  If not, write to the
Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
02110-1301 USA.

Linking this library statically or dynamically with other modules is
making a combined work based on this library.  Thus, the terms and
conditions of the GNU General Public License cover the whole
combination.

As a special exception, the copyright holders of this library give you
permission to link this library with independent modules to produce an
executable, regardless of the license terms of these independent
modules, and to copy and distribute the resulting executable under
terms of your choice, provided that you also meet, for each linked
independent module, the terms and conditions of the license of that
module.  An independent module is a module which is not derived from
or based on this library.  If you modify this library, you may extend
this exception to your version of the library, but you are not
obligated to do so.  If you do not wish to do so, delete this
exception statement from your version. */


package javax.swing.plaf.basic;

import java.awt.Dimension;
import java.awt.Graphics;

import javax.swing.JComponent;
import javax.swing.JSeparator;
import javax.swing.UIDefaults;
import javax.swing.UIManager;
import javax.swing.plaf.ComponentUI;

/**
 * The Basic Look and Feel UI delegate for Separator.
 */
public class BasicToolBarSeparatorUI extends BasicSeparatorUI
{
  private transient Dimension size;

  /**
   * Creates a new UI delegate for the given JComponent.
   *
   * @param c The JComponent to create a delegate for.
   *
   * @return A new BasicToolBarSeparatorUI.
   */
  public static ComponentUI createUI(JComponent c)
  {
    return new BasicToolBarSeparatorUI();
  }

  /**
   * This method installs the defaults that are given by the Basic L&F.
   *
   * @param s The Separator that is being installed.
   */
  protected void installDefaults(JSeparator s)
  {
    UIDefaults defaults = UIManager.getLookAndFeelDefaults();
    
    size = defaults.getDimension("ToolBar.separatorSize");
  }

  /**
   * This method does nothing as a Separator is just blank space.
   *
   * @param g The Graphics object to paint with
   * @param c The JComponent to paint.
   */
  public void paint(Graphics g, JComponent c)
  {
    // Do nothing.
  }

  /**
   * This method returns the preferred size of the  JComponent.
   *
   * @param c The JComponent to measure.
   *
   * @return The preferred size.
   */
  public Dimension getPreferredSize(JComponent c)
  {
    return size;
  }

  /**
   * This method returns the minimum size of the JComponent.
   *
   * @param c The JComponent to measure.
   *
   * @return The minimum size.
   */
  public Dimension getMinimumSize(JComponent c)
  {
    return size;
  }

  /**
   * This method returns the maximum size of the JComponent.
   *
   * @param c The JComponent to measure.
   *
   * @return The maximum size.
   */
  public Dimension getMaximumSize(JComponent c)
  {
    return size;
  }
}
